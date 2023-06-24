package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	remoteexecution "github.com/bazelbuild/remote-apis/build/bazel/remote/execution/v2"
	"github.com/buildbarn/bb-browser/pkg/proto/configuration/bb_browser"
	"github.com/buildbarn/bb-remote-execution/pkg/proto/resourceusage"
	"github.com/buildbarn/bb-storage/pkg/auth"
	"github.com/buildbarn/bb-storage/pkg/blobstore"
	blobstore_configuration "github.com/buildbarn/bb-storage/pkg/blobstore/configuration"
	"github.com/buildbarn/bb-storage/pkg/digest"
	"github.com/buildbarn/bb-storage/pkg/global"
	"github.com/buildbarn/bb-storage/pkg/proto/iscc"
	"github.com/buildbarn/bb-storage/pkg/util"
	"github.com/dustin/go-humanize"
	"github.com/gorilla/mux"
	"github.com/kballard/go-shellquote"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// rfc3339Milli is identical similar to the time.RFC3339 and
	// time.RFC3339Nano formats, except that it shows the time in
	// milliseconds.
	rfc3339Milli = "2006-01-02T15:04:05.999Z07:00"
)

// timestampDelta is returned by the timestamp_proto_delta, returning a
// timestamp and a duration relative to a previous timestamp value. It
// can be used to display split times.
type timestampDelta struct {
	Time                 time.Time
	DurationFromPrevious time.Duration
}

type certInfo struct {
	mu         sync.Mutex
	x509Certs  []*x509.Certificate
	privateKey crypto.Signer
}

var (
	//go:embed templates
	templatesFS embed.FS
	//go:embed stylesheet.css
	stylesheet template.CSS
	//go:embed favicon.png
	favicon []byte

	ci certInfo
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Usage: bb_browser bb_browser.jsonnet")
	}
	var configuration bb_browser.ApplicationConfiguration
	if err := util.UnmarshalConfigurationFromFile(os.Args[1], &configuration); err != nil {
		log.Fatalf("Failed to read configuration from %s: %s", os.Args[1], err)
	}
	lifecycleState, grpcClientFactory, err := global.ApplyConfiguration(configuration.Global, nil)
	if err != nil {
		log.Fatal("Failed to apply global configuration options: ", err)
	}

	// Storage access.
	contentAddressableStorage, actionCache, err := blobstore_configuration.NewCASAndACBlobAccessFromConfiguration(
		configuration.Blobstore,
		grpcClientFactory,
		int(configuration.MaximumMessageSizeBytes))
	if err != nil {
		log.Fatal(err)
	}

	authorizerFactory := auth.DefaultAuthorizerFactory
	authorizer, err := authorizerFactory.NewAuthorizerFromConfiguration(configuration.Authorizer)
	if err != nil {
		log.Fatal("Failed to create authorizer: ", err)
	}

	// nil the put and findMissing authorizers - bb-browser shouldn't ever use these APIs.
	contentAddressableStorage = blobstore.NewAuthorizingBlobAccess(contentAddressableStorage, authorizer, nil, nil)
	actionCache = blobstore.NewAuthorizingBlobAccess(actionCache, authorizer, nil, nil)

	var initialSizeClassCache blobstore.BlobAccess
	if configuration.InitialSizeClassCache == nil {
		initialSizeClassCache = blobstore.NewErrorBlobAccess(status.Error(codes.NotFound, "No Initial Size Class Cache configured"))
	} else {
		info, err := blobstore_configuration.NewBlobAccessFromConfiguration(
			configuration.InitialSizeClassCache,
			blobstore_configuration.NewISCCBlobAccessCreator(
				grpcClientFactory,
				int(configuration.MaximumMessageSizeBytes)))
		if err != nil {
			log.Fatal("Failed to create Initial Size Class Cache: ", err)
		}
		initialSizeClassCache = blobstore.NewAuthorizingBlobAccess(info.BlobAccess, authorizer, nil, nil)
	}

	routePrefix := path.Join("/", configuration.RoutePrefix)
	if !strings.HasSuffix(routePrefix, "/") {
		routePrefix += "/"
	}

	faviconURL := template.URL("data:image/png;base64," + base64.URLEncoding.EncodeToString(favicon))
	templates, err := template.New("templates").Funcs(template.FuncMap{
		"basename":    path.Base,
		"favicon_url": func() template.URL { return faviconURL },
		"humanize_bytes": func(v interface{}) string {
			switch i := v.(type) {
			case uint64:
				return humanize.Bytes(i)
			case int64:
				return humanize.Bytes(uint64(i))
			default:
				panic("Unknown type")
			}
		},
		"inc": func(n int) int {
			return n + 1
		},
		"stylesheet": func() template.CSS { return stylesheet },
		"to_outcome_failed": func(previousExecution *iscc.PreviousExecution) bool {
			_, ok := previousExecution.Outcome.(*iscc.PreviousExecution_Failed)
			return ok
		},
		"to_outcome_timed_out": func(previousExecution *iscc.PreviousExecution) *time.Duration {
			if outcome, ok := previousExecution.Outcome.(*iscc.PreviousExecution_TimedOut); ok {
				if outcome.TimedOut.CheckValid() == nil {
					d := outcome.TimedOut.AsDuration()
					return &d
				}
			}
			return nil
		},
		"to_outcome_succeeded": func(previousExecution *iscc.PreviousExecution) *time.Duration {
			if outcome, ok := previousExecution.Outcome.(*iscc.PreviousExecution_Succeeded); ok {
				if outcome.Succeeded.CheckValid() == nil {
					d := outcome.Succeeded.AsDuration()
					return &d
				}
			}
			return nil
		},
		"to_build_executor_resource_usage": func(any *anypb.Any) *resourceusage.BuildExecutorResourceUsage {
			var pb resourceusage.BuildExecutorResourceUsage
			if err := any.UnmarshalTo(&pb); err != nil {
				return nil
			}
			return &pb
		},
		"to_monetary_resource_usage": func(any *anypb.Any) *resourceusage.MonetaryResourceUsage {
			var pb resourceusage.MonetaryResourceUsage
			if err := any.UnmarshalTo(&pb); err != nil {
				return nil
			}
			return &pb
		},
		"to_file_pool_resource_usage": func(any *anypb.Any) *resourceusage.FilePoolResourceUsage {
			var pb resourceusage.FilePoolResourceUsage
			if any.UnmarshalTo(&pb) != nil {
				return nil
			}
			return &pb
		},
		"to_posix_resource_usage": func(any *anypb.Any) *resourceusage.POSIXResourceUsage {
			var pb resourceusage.POSIXResourceUsage
			if any.UnmarshalTo(&pb) != nil {
				return nil
			}
			return &pb
		},
		"to_request_metadata": func(any *anypb.Any) *remoteexecution.RequestMetadata {
			var pb remoteexecution.RequestMetadata
			if any.UnmarshalTo(&pb) != nil {
				return nil
			}
			return &pb
		},
		"to_worker_id": func(worker string) map[string]string {
			var workerID map[string]string
			if json.Unmarshal([]byte(worker), &workerID) != nil {
				return nil
			}
			return workerID
		},
		"shellquote": shellquote.Join,
		"timestamp_rfc3339": func(t time.Time) string {
			// Converts a timestamp to RFC3339 format.
			return t.Format(rfc3339Milli)
		},
		"timestamp_proto_delta": func(pbPrevious, pbNow *timestamppb.Timestamp) *timestampDelta {
			if err := pbNow.CheckValid(); err != nil {
				return nil
			}
			tNow := pbNow.AsTime()
			if err := pbPrevious.CheckValid(); err != nil {
				// Time may be parsed, but no split time
				// is available.
				return &timestampDelta{
					Time: tNow,
				}
			}
			tPrevious := pbPrevious.AsTime()
			if tNow.Equal(tPrevious) {
				// Don't display the split time, as
				// there is no difference.
				return nil
			}
			return &timestampDelta{
				Time:                 tNow,
				DurationFromPrevious: tNow.Sub(tPrevious),
			}
		},
		"timestamp_proto_rfc3339": func(pb *timestamppb.Timestamp) string {
			// Converts a Protobuf timestamp to RFC 3339 format.
			if pb.CheckValid() != nil {
				return ""
			}
			return pb.AsTime().Format(rfc3339Milli)
		},
	}).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		log.Fatal("Failed to parse HTML templates: ", err)
	}

	// Prefix to add to instance names that are placed in bb_clientd
	// pathname strings.
	bbClientdInstanceNamePrefix, err := digest.NewInstanceName(configuration.BbClientdInstanceNamePrefix)
	if err != nil {
		log.Fatalf("Invalid instance name %#v: %s", configuration.BbClientdInstanceNamePrefix, err)
	}
	bbClientdInstanceNamePatcher := digest.NewInstanceNamePatcher(digest.EmptyInstanceName, bbClientdInstanceNamePrefix)

	router := mux.NewRouter()
	subrouter := router.PathPrefix(routePrefix).Subrouter()
	NewBrowserService(
		contentAddressableStorage,
		actionCache,
		initialSizeClassCache,
		int(configuration.MaximumMessageSizeBytes),
		templates,
		bbClientdInstanceNamePatcher,
		subrouter)
	go func() {
		if configuration.Tls != nil {
			log.Printf("Using server name %s\n", configuration.ServerName)
			cfg := &tls.Config{
				ClientAuth: tls.NoClientCert,
				ServerName: configuration.ServerName,
			}
			if util.IsPEMFile(configuration.Tls.ServerCertificate) && util.IsPEMFile(configuration.Tls.ServerPrivateKey) {
				ci.mu.Lock()
				err = loadNewCerts(configuration.Tls.ServerCertificate, configuration.Tls.ServerPrivateKey)
				ci.mu.Unlock()
				if err != nil {
					log.Fatal(err.Error())
				}
				cfg.GetCertificate = getCertificate(configuration.Tls.ServerCertificate, configuration.Tls.ServerPrivateKey)
			} else {
				cert, err := tls.X509KeyPair([]byte(configuration.Tls.ServerCertificate), []byte(configuration.Tls.ServerPrivateKey))
				if err != nil {
					log.Fatal("Invalid server certificate or private key: %v", err)
				}
				cfg.Certificates = []tls.Certificate{cert}
			}
			l, err := tls.Listen("tcp", configuration.ListenAddress, cfg)
			if err != nil {
				log.Fatal("can't listen: %v", err)
			}
			log.Fatal(http.Serve(l, router))
		} else {
			// Use nonTLS connections.
			log.Fatal(http.ListenAndServe(configuration.ListenAddress, router))
		}
	}()

	lifecycleState.MarkReadyAndWait()
}

func loadNewCerts(certFile, keyFile string) error {
	cb, err := ioutil.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("can't read certs: %v", err)
	}
	kb, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("can't read key: %v", err)
	}
	svid, err := x509svid.Parse(cb, kb)
	if err != nil {
		return fmt.Errorf("can't parse certs/key: %v", err)
	}
	ci.x509Certs = svid.Certificates
	ci.privateKey = svid.PrivateKey
	return nil
}

func getCertificate(certFile, keyFile string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		ci.mu.Lock()
		defer ci.mu.Unlock()
		log.Printf("ClientHelloInfo: %#v\n", info)
		log.Printf("CI: getCert not before %v not after %v\n", ci.x509Certs[0].NotBefore, ci.x509Certs[0].NotAfter)
		if time.Now().After(ci.x509Certs[0].NotAfter.Add(time.Minute * -15)) {
			// Cert is about to expire.  Some external entity is responsible for rotating certs.
			// Reload the new ones.
			if err := loadNewCerts(certFile, keyFile); err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "Can't reload certs: %v\n", err)
			}
			log.Printf("CI: Reload: getCert not before %v not after %v\n", ci.x509Certs[0].NotBefore, ci.x509Certs[0].NotAfter)
		}
		cert := &tls.Certificate {
			Certificate: make([][]byte, 0, len(ci.x509Certs)),
			PrivateKey:  ci.privateKey,
		}
		for _, c := range ci.x509Certs {
			cert.Certificate = append(cert.Certificate, c.Raw)
		}
		return cert, nil
	}
}
