package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
)

// ErrExtensionNotExist is returned when an extension is not supported by the library
type ErrExtensionNotExist string

// Error is the error value which contains the extension that does not exist
func (e ErrExtensionNotExist) Error() string {
	return fmt.Sprintf("Extension does not exist: %s\n", string(e))
}

func stringToSpec(ja3 string) (*tls.ClientHelloSpec, error) {
	var extMap = map[string]tls.TLSExtension{
		"0": &tls.SNIExtension{},
		"5": &tls.StatusRequestExtension{},
		// These are applied later
		// "10": &tls.SupportedCurvesExtension{...}
		// "11": &tls.SupportedPointsExtension{...}
		"13": &tls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1,
			},
		},
		"16": &tls.ALPNExtension{
			AlpnProtocols: []string{"h2", "http/1.1"},
		},
		"18": &tls.SCTExtension{},
		"21": &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		"23": &tls.UtlsExtendedMasterSecretExtension{},
		"27": &tls.FakeCertCompressionAlgsExtension{},
		"28": &tls.FakeRecordSizeLimitExtension{},
		"35": &tls.SessionTicketExtension{},
		"43": &tls.SupportedVersionsExtension{Versions: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.VersionTLS13,
			tls.VersionTLS12,
			tls.VersionTLS11,
			tls.VersionTLS10}},
		"44": &tls.CookieExtension{},
		"45": &tls.PSKKeyExchangeModesExtension{
			Modes: []uint8{
				tls.PskModeDHE,
			}},
		"51":    &tls.KeyShareExtension{KeyShares: []tls.KeyShare{}},
		"13172": &tls.NPNExtension{},
		"65281": &tls.RenegotiationInfoExtension{
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
	}

	tokens := strings.Split(ja3, ",")

	version := tokens[0]
	ciphers := strings.Split(tokens[1], "-")
	extensions := strings.Split(tokens[2], "-")
	curves := strings.Split(tokens[3], "-")
	if len(curves) == 1 && curves[0] == "" {
		curves = []string{}
	}
	pointFormats := strings.Split(tokens[4], "-")
	if len(pointFormats) == 1 && pointFormats[0] == "" {
		pointFormats = []string{}
	}

	// parse curves
	var targetCurves []tls.CurveID
	for _, c := range curves {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		targetCurves = append(targetCurves, tls.CurveID(cid))
	}
	extMap["10"] = &tls.SupportedCurvesExtension{Curves: targetCurves}

	// parse point formats
	var targetPointFormats []byte
	for _, p := range pointFormats {
		pid, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, err
		}
		targetPointFormats = append(targetPointFormats, byte(pid))
	}
	extMap["11"] = &tls.SupportedPointsExtension{SupportedPoints: targetPointFormats}

	// build extenions list
	var exts []tls.TLSExtension
	for _, e := range extensions {
		te, ok := extMap[e]
		if !ok {
			return nil, ErrExtensionNotExist(e)
		}
		exts = append(exts, te)
	}
	// build SSLVersion
	vid64, err := strconv.ParseUint(version, 10, 16)
	if err != nil {
		return nil, err
	}
	vid := uint16(vid64)

	// build CipherSuites
	var suites []uint16
	for _, c := range ciphers {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		suites = append(suites, uint16(cid))
	}

	return &tls.ClientHelloSpec{
		TLSVersMin:         vid,
		TLSVersMax:         vid,
		CipherSuites:       suites,
		CompressionMethods: []byte{0},
		Extensions:         exts,
		GetSessionID:       sha256.Sum256,
	}, nil
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()
	clientReader := bufio.NewReader(clientConn)

	// process CONNECT
	connectReq, err := http.ReadRequest(clientReader)
	if err != nil {
		fmt.Println("Failed to read CONNECT request: " + err.Error())
		return
	}
	if connectReq.Method != "CONNECT" {
		//fmt.Println("Initial request is not a CONNECT")
		return
	}
	destAddr := connectReq.Host
	realDestAddr := destAddr
	hostname := strings.Split(destAddr, ":")[0]
	proxyAddr := connectReq.Header.Get("Proxy")
	ja3String := connectReq.Header.Get("JA3")
	if ja3String == "" {
		//fmt.Println("JA3 header was not found in CONNECT request")
		return
	}
	if proxyAddr != "" {
		realDestAddr = proxyAddr
	}

	// connect to server
	config := &tls.Config{ServerName: hostname}
	spec, err := stringToSpec(ja3String)
	if err != nil {
		//fmt.Println("Failed to create ClientHelloSpec: " + err.Error())
		return
	}

	destConn, err := net.DialTimeout("tcp4", realDestAddr, time.Second*60)
	if err != nil {
		//fmt.Println("Failed to connect to " + realDestAddr + ": " + err.Error())
		return
	}

	if proxyAddr != "" {
		proxyConnectReq := &http.Request{Method: "CONNECT", URL: &url.URL{Host: destAddr}}
		proxyConnectReq.Write(destConn)
		proxyConnectResp, err := http.ReadResponse(bufio.NewReader(destConn), proxyConnectReq)

		if err != nil {
			return
		}

		if proxyConnectResp.StatusCode >= 300 {
			return
		}
	}

	destConnTls := tls.UClient(destConn, config, tls.HelloCustom)
	defer destConnTls.Close()
	destConnTls.ApplyPreset(spec)
	err = destConnTls.Handshake()
	if err != nil {
		//fmt.Println("Failed to establish handshake: " + err.Error())
		return
	}
	destReader := bufio.NewReader(destConnTls)

	connectResp := http.Response{StatusCode: 200, Status: "OK", ProtoMajor: 1, ProtoMinor: 1}
	connectResp.Write(clientConn)

	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			//fmt.Println("Failed to read request from client: " + err.Error())
			return
		}
		req.Host = hostname
		req.Write(destConnTls)

		resp, err := http.ReadResponse(destReader, req)
		if err != nil {
			//fmt.Println("Failed to read response from destination: " + err.Error())
			return
		}
		resp.Write(clientConn)
	}

}

func main() {
	if len(os.Args) == 1 {
		fmt.Println("No bind address was provided")
		return
	}

	bindAddr := os.Args[1]
	l, err := net.Listen("tcp4", bindAddr)
	if err != nil {
		fmt.Println("Failed to create socket: " + err.Error())
		return
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println("Failed to accept connection: " + err.Error())
			continue
		}
		go handleConnection(c)
	}
}
