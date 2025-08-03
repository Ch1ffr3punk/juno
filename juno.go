package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/smtp"
	"net/textproto"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

var (
	certFile = flag.String("cert", "", "Path to TLS certificate file")
	keyFile  = flag.String("key", "", "Path to TLS private key file")
)

var emailRegExp = regexp.MustCompile(`^<((\S+)@(\S+\.\S+))>$`)
var mailQueue chan *Envelope
var mailQueueMutex sync.Mutex

const (
	TorSocksProxyAddr = "127.0.0.1:9050"
	RelayWorkerCount  = 5
	DeliveryTimeout   = 30 * time.Second
)

type Server struct {
	Name      string
	Addr      string
	Handler   Handler
	TLSConfig *tls.Config
	Debug     bool
	ErrorLog  *log.Logger
}

type conn struct {
	remoteAddr    string
	server        *Server
	rwc           net.Conn
	text          *textproto.Conn
	tlsState      *tls.ConnectionState
	fromAgent     string
	mailFrom      string
	mailTo        []string
	mailData      *bytes.Buffer
	helloRecieved bool
	quitSent      bool
	mu            sync.Mutex
}

type Envelope struct {
	FromAgent           string
	RemoteAddr          string
	OriginalMessageFrom string
	MessageFrom         string
	MessageTo           string
	MessageData         io.Reader
	ReceivedAt          time.Time
	RetryCount          int
}

type HandlerFunc func(envelope *Envelope) error

func (f HandlerFunc) ServeSMTP(envelope *Envelope) error {
	return f(envelope)
}

type Handler interface {
	ServeSMTP(envelope *Envelope) error
}

type ServeMux struct {
	mu     sync.RWMutex
	m      map[string]map[string]muxEntry
	server *Server
}

type muxEntry struct {
	h       Handler
	pattern string
}

type torListener struct {
	net.Listener
}

func (l *torListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (srv *Server) logf(format string, args ...interface{}) {
	if srv.ErrorLog != nil {
		srv.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (srv *Server) logfd(format string, args ...interface{}) {
	if srv.Debug {
	}
}

func (srv *Server) newConn(rwc net.Conn) (c *conn, err error) {
	c = &conn{
		remoteAddr: rwc.RemoteAddr().String(),
		server:     srv,
		rwc:        rwc,
		text:       textproto.NewConn(rwc),
		mailTo:     make([]string, 0),
	}
	return c, nil
}

func (srv *Server) ListenAndServe() error {
	if srv.Name == "" {
		srv.Name = "juno"
	}
	addr := srv.Addr
	if addr == "" {
		addr = ":smtp"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

func (srv *Server) ListenAndServeTLS() error {
	config := &tls.Config{}
	if srv.TLSConfig != nil {
		*config = *srv.TLSConfig
	}
	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	srv.TLSConfig = config
	return srv.ListenAndServe()
}

func (srv *Server) Serve(l net.Listener) error {
	defer l.Close()
	var tempDelay time.Duration
	for {
		rw, e := l.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				srv.logf("smtp: Accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		tempDelay = 0
		c, err := srv.newConn(rw)
		if err != nil {
			continue
		}
		go c.serve()
	}
}

func (srv *Server) ServeTLS(l net.Listener) error {
	config := &tls.Config{}
	if srv.TLSConfig != nil {
		*config = *srv.TLSConfig
	}
	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	srv.TLSConfig = config
	return srv.Serve(l)
}

func (c *conn) serve() {
	c.server.logf("INFO: Connection established from %s", c.remoteAddr)
	err := c.text.PrintfLine("%d %s %s", 220, c.server.Name, "ESMTP")
	if err != nil {
		c.server.logf("ERROR: Connection error")
		return
	}
	for !c.quitSent && err == nil {
		err = c.readCommand()
	}
	c.text.Close()
	c.rwc.Close()
	c.server.logf("INFO: Connection closed")
}

func (c *conn) resetSession() {
	c.mailFrom = ""
	c.mailTo = make([]string, 0)
	c.mailData = nil
}

func isOnionDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}
	return strings.HasSuffix(domain, ".onion")
}

func SplitAddress(address string) (string, string, error) {
	if !strings.Contains(address, "@") {
		return "", "", errors.New("invalid email address format: missing '@'")
	}
	sepInd := strings.LastIndex(address, "@")
	if sepInd == -1 {
		return "", "", errors.New("invalid email address format")
	}
	localPart := address[:sepInd]
	domainPart := address[sepInd+1:]
	if !isOnionDomain(domainPart) {
		return "", "", errors.New("only .onion domains are allowed")
	}
	return localPart, domainPart, nil
}

func (c *conn) readCommand() error {
	s, err := c.text.ReadLine()
	if err != nil {
		return err
	}
	parts := strings.Split(s, " ")
	if len(parts) <= 0 {
		return c.text.PrintfLine("%d %s", 500, "Command not recognized")
	}
	parts[0] = strings.ToUpper(parts[0])
	switch parts[0] {
	case "HELO", "EHLO":
		if len(parts) < 2 {
			return c.text.PrintfLine("%d %s", 501, "Not enough arguments")
		}
		c.fromAgent = parts[1]
		c.resetSession()
		c.helloRecieved = true
		responses := []string{
			fmt.Sprintf("%d-%s %s", 250, "Greets", parts[1]),
			fmt.Sprintf("%d-%s", 250, "PIPELINING"),
			fmt.Sprintf("%d-%s", 250, "SMTPUTF8"),
		}
		if c.server.TLSConfig != nil && c.tlsState == nil {
			responses = append([]string{fmt.Sprintf("%d-%s", 250, "STARTTLS")}, responses...)
		}
		for i, resp := range responses {
			if i == len(responses)-1 {
				resp = strings.Replace(resp, "-", " ", 1)
			}
			if err := c.text.PrintfLine(resp); err != nil {
				return err
			}
		}
		return nil
	case "STARTTLS":
		if c.server.TLSConfig == nil {
			return c.text.PrintfLine("%d %s", 454, "TLS unavailable on the server")
		}
		if c.tlsState != nil {
			return c.text.PrintfLine("%d %s", 454, "TLS session already active")
		}
		if err := c.text.PrintfLine("%d %s", 220, "Ready to start TLS"); err != nil {
			return err
		}
		tlsconn := tls.Server(c.rwc, c.server.TLSConfig)
		if err := tlsconn.Handshake(); err != nil {
			return err
		}
		c.rwc = tlsconn
		c.text = textproto.NewConn(c.rwc)
		state := tlsconn.ConnectionState()
		c.tlsState = &state
		c.resetSession()
		c.helloRecieved = false
		return nil
	case "MAIL":
		if c.mailFrom != "" {
			return c.text.PrintfLine("%d %s", 503, "MAIL command already received")
		}
		if len(parts) < 2 {
			return c.text.PrintfLine("%d %s", 501, "Not enough arguments")
		}
		if !strings.HasPrefix(parts[1], "FROM:") {
			return c.text.PrintfLine("%d %s", 501, "MAIL command must be immediately succeeded by 'FROM:'")
		}
		from := parts[1][5:]
		if !emailRegExp.MatchString(from) {
			return c.text.PrintfLine("%d %s", 501, "MAIL command contained invalid address")
		}
		email := emailRegExp.FindStringSubmatch(from)[1]
		if _, _, err := SplitAddress(email); err != nil && !strings.Contains(email, "@") {
		}
		c.mailFrom = email
		return c.text.PrintfLine("%d %s", 250, "Ok")
	case "RCPT":
		if c.mailFrom == "" {
			return c.text.PrintfLine("%d %s", 503, "Bad sequence of commands")
		}
		if len(parts) < 2 {
			return c.text.PrintfLine("%d %s", 501, "Not enough arguments")
		}
		if !strings.HasPrefix(parts[1], "TO:") {
			return c.text.PrintfLine("%d %s", 501, "RCPT command must be immediately succeeded by 'TO:'")
		}
		to := parts[1][3:]
		if !emailRegExp.MatchString(to) {
			return c.text.PrintfLine("%d %s", 501, "RCPT command contained invalid address")
		}
		email := emailRegExp.FindStringSubmatch(to)[1]
		c.mailTo = append(c.mailTo, email)
		return c.text.PrintfLine("%d %s", 250, "Ok")
	case "DATA":
		if len(c.mailTo) == 0 || c.mailFrom == "" {
			return c.text.PrintfLine("%d %s", 503, "Bad sequence of commands")
		}
		if err := c.text.PrintfLine("%d %s", 354, "End data with <CR><LF>.<CR><LF>"); err != nil {
			return err
		}
		data, err := c.text.ReadDotBytes()
		if err != nil {
			return err
		}
		c.mailData = bytes.NewBuffer(data)

		for _, recipient := range c.mailTo {
			env := &Envelope{
				FromAgent:           c.fromAgent,
				RemoteAddr:          c.remoteAddr,
				OriginalMessageFrom: c.mailFrom,
				MessageFrom:         c.mailFrom,
				MessageTo:           recipient,
				MessageData:         bytes.NewReader(c.mailData.Bytes()),
				ReceivedAt:          time.Now(),
				RetryCount:          0,
			}
			c.server.logf("INFO: Received mail")
			if err := c.server.Handler.ServeSMTP(env); err != nil {
				c.server.logf("ERROR: Failed to handle mail")
				return c.text.PrintfLine("%d %s", 554, "Transaction failed")
			}
		}
		c.resetSession()
		return c.text.PrintfLine("%d %s", 250, "OK")
	case "RSET":
		c.resetSession()
		return c.text.PrintfLine("%d %s", 250, "Ok")
	case "VRFY", "EXPN", "HELP", "NOOP":
		return c.text.PrintfLine("%d %s", 250, "OK")
	case "QUIT":
		c.quitSent = true
		return c.text.PrintfLine("%d %s", 221, "OK")
	default:
		return c.text.PrintfLine("%d %s", 500, "Command not recognized")
	}
}

func NewServeMux(srv *Server) *ServeMux {
	return &ServeMux{
		m:      make(map[string]map[string]muxEntry),
		server: srv,
	}
}

var DefaultServeMux *ServeMux

func CanonicalizeEmail(local string) string {
	local = strings.TrimSpace(local)
	local = strings.ToLower(local)
	local = strings.Replace(local, ".", "", -1)
	if li := strings.LastIndex(local, "+"); li > 0 {
		local = local[:li]
	}
	return local
}

func (mux *ServeMux) Handle(pattern string, handler Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()
	parts := strings.SplitN(pattern, "@", 2)
	if len(parts) != 2 {
		log.Fatalf("invalid pattern format for ServeMux.Handle: %s", pattern)
	}
	localPart := CanonicalizeEmail(parts[0])
	if localPart == "" {
		localPart = "*"
	}
	domainPart := parts[1]
	if _, ok := mux.m[domainPart]; !ok {
		mux.m[domainPart] = make(map[string]muxEntry)
	}
	mux.m[domainPart][localPart] = muxEntry{h: handler, pattern: pattern}
}

func (mux *ServeMux) HandleFunc(pattern string, handler func(envelope *Envelope) error) {
	mux.Handle(pattern, HandlerFunc(handler))
}

func (mux *ServeMux) ServeSMTP(envelope *Envelope) error {
	localPart, domainPart, err := SplitAddress(envelope.MessageTo)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}
	canonicalLocal := CanonicalizeEmail(localPart)
	mux.mu.RLock()
	defer mux.mu.RUnlock()

	if domainHandlers, ok := mux.m[domainPart]; ok {
		if handler, ok := domainHandlers[canonicalLocal]; ok {
			return handler.h.ServeSMTP(envelope)
		}
		if handler, ok := domainHandlers["*"]; ok {
			return handler.h.ServeSMTP(envelope)
		}
	}
	
	// Default handler - just relay the message
	return smtpRelay(envelope)
}

func createTorListener(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host != "127.0.0.1" && host != "localhost" {
		return nil, errors.New("server must listen on localhost for Tor hidden service")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &torListener{Listener: listener}, nil
}

func smtpRelay(envelope *Envelope) error {
	_, domain, err := SplitAddress(envelope.MessageTo)
	if err != nil {
		return fmt.Errorf("invalid recipient address")
	}

	targetAddr := net.JoinHostPort(domain, "2525")
	dialer := &net.Dialer{Timeout: DeliveryTimeout}
	torDialer, err := proxy.SOCKS5("tcp", TorSocksProxyAddr, nil, dialer)
	if err != nil {
		return fmt.Errorf("Failed to create Tor dialer: %w", err)
	}
	conn, err := torDialer.Dial("tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("Failed to connect to relay target")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(DeliveryTimeout))
	client, err := smtp.NewClient(conn, domain)
	if err != nil {
		return fmt.Errorf("Failed to create SMTP client: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		cfg := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
		}
		if err := client.StartTLS(cfg); err != nil {
			log.Printf("WARNING: Failed to STARTTLS with relay target")
		}
	}

	if err := client.Mail(envelope.MessageFrom); err != nil {
		return fmt.Errorf("MAIL FROM failed")
	}

	if err := client.Rcpt(envelope.MessageTo); err != nil {
		return fmt.Errorf("RCPT TO failed")
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed")
	}
	defer wc.Close()

	if _, err := io.Copy(wc, envelope.MessageData); err != nil {
		return fmt.Errorf("message transfer failed")
	}
	return nil
}

func queueEnvelope(envelope *Envelope) bool {
	mailQueueMutex.Lock()
	defer mailQueueMutex.Unlock()
	select {
	case mailQueue <- envelope:
		log.Printf("INFO: Mail queued for delivery.")
		return true
	default:
		return false
	}
}

func StartRelayWorkers(queue chan *Envelope, workerCount int) {
	for i := 0; i < workerCount; i++ {
		go func(id int) {
			log.Printf("INFO: Relay Worker %d started", id)
			for env := range queue {
				log.Printf("INFO: Worker %d: Processing mail.", id)
				err := smtpRelay(env)
				if err != nil {
					log.Printf("ERROR: Worker %d: Failed to deliver mail")
					if env.RetryCount < 9 {
						env.RetryCount++
						time.Sleep(time.Duration(env.RetryCount) * 5 * time.Second)
						if !queueEnvelope(env) {
							log.Printf("WARNING: Worker %d: Failed to requeue message.", id)
						}
					} else {
						log.Printf("ERROR: Worker %d: Permanent failure after %d retries.", id, env.RetryCount)
					}
				} else {
					log.Printf("INFO: Worker %d: Successfully delivered mail.", id)
				}
			}
			log.Printf("INFO: Relay Worker %d stopped", id)
		}(i)
	}
}

func main() {
	flag.Parse()
	if *certFile == "" || *keyFile == "" {
		log.Fatal("Both -cert and -key flags are required")
	}

	mailQueue = make(chan *Envelope, 100)
	StartRelayWorkers(mailQueue, RelayWorkerCount)

	server := &Server{
		Name:  "juno",
		Addr:  "127.0.0.1:2525",
		Debug: false,
	}

	DefaultServeMux = NewServeMux(server)
	server.Handler = DefaultServeMux

	listener, err := createTorListener(server.Addr)
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}

	log.Printf("INFO: Starting SMTP server on %s", server.Addr)
	log.Printf("INFO: Using Tor proxy at %s", TorSocksProxyAddr)
	log.Printf("INFO: Started %d relay workers", RelayWorkerCount)

	if err := server.ServeTLS(listener); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}