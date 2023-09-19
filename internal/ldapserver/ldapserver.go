package ldapserver

import (
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	stdlog "log"

	"github.com/blesswinsamuel/ldap-sql-proxy/internal/provider"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/lor00x/goldap/message"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	ldap "github.com/vjeantet/ldapserver"
	"golang.org/x/crypto/bcrypt"
)

var (
	ldapRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "ldap_sql_adapter_ldap_request_duration_seconds",
		Help: "Duration of LDAP request requests.",
	}, []string{"query_name", "status"})
)

// https://github.com/glauth/glauth/blob/0e7769ff841e096dbf0cb67768cbd2ab7142f6fb/v2/pkg/handler/ldap.go#L62
// https://github.com/authelia/authelia/blob/ae8d25f4be3b4ff880dd847b9fa40e1c56d0ddc8/internal/authentication/ldap_user_provider.go#L240
// https://github.com/jimlambrt/ldap/blob/2ad3888755a37c65bd1fea35b347e8e7bf414f6e/testdirectory/directory.go#L129
// https://github.com/vjeantet/ldapserver/blob/master/examples/complex/main.go
// https://github.com/jiegec/daccountd/blob/427ad2b20c866be9a84db3c0aec6a8823b026ef6/ldap.go#L36

type Config struct {
	BindUsername string
	BindPassword string
	BaseDN       string
}

type LdapServer struct {
	provider provider.Provider
	srv      *ldap.Server
	config   Config
}

func NewLdapServer(provider provider.Provider, config Config) *LdapServer {
	s := &LdapServer{provider: provider, config: config}
	ldap.Logger = stdlog.New(os.Stdout, "[ldap] ", stdlog.LstdFlags)
	ldap.Logger.(*stdlog.Logger).SetOutput(io.Discard)
	var err error
	s.srv = ldap.NewServer()
	if err != nil {
		log.Fatal().Msgf("unable to create server: %s", err.Error())
	}
	routes := ldap.NewRouteMux()
	routes.Abandon(s.handleAbandon)
	routes.Bind(s.handleBind)
	routes.Search(s.handleSearchDSE).
		BaseDn("").
		Scope(ldap.SearchRequestScopeBaseObject).
		Filter("(objectclass=*)")
	routes.Search(s.handleSearchUsers).
		BaseDn("ou=people," + config.BaseDN).
		Scope(ldap.SearchRequestHomeSubtree)
	routes.Search(s.handleSearchGroups).
		BaseDn("ou=groups," + config.BaseDN).
		Scope(ldap.SearchRequestHomeSubtree)

	routes.Extended(s.passwordModifyHandler).
		RequestName(ldap.NoticeOfPasswordModify).Label("Ext - PasswordModify")

	routes.NotFound(s.handleNotFound)

	s.srv.Handle(routes)
	return s
}

type ldapInstrumentor func(status string, errCode string)

func instrumentor(queryName string) ldapInstrumentor {
	startTime := time.Now()
	return func(status string, errCode string) {
		ldapRequestDuration.WithLabelValues(queryName, status).Observe(time.Since(startTime).Seconds())
	}
}

func initRequest(name string, customLogFields func(zerolog.Context) zerolog.Context) (ins ldapInstrumentor, logger zerolog.Logger, ctx context.Context) {
	logctx := log.With().Str("method", name)
	if customLogFields != nil {
		logctx = customLogFields(logctx)
	}
	logger = logctx.Logger()
	ctx = logger.WithContext(context.Background())
	ins = instrumentor(name)
	logger.Debug().Msg("request started")
	return
}

func (s *LdapServer) handleNotFound(w ldap.ResponseWriter, r *ldap.Message) {
	ins, _, ctx := initRequest("not-found", func(ctx zerolog.Context) zerolog.Context {
		return ctx.
			Int("id", r.MessageID().Int()).
			Str("protocol_op_name", r.ProtocolOpName()).
			Int("protocol_op_type", r.ProtocolOpType())
	})

	writeErrorResponse(ctx, w, ins, ldap.NewResponse(ldap.LDAPResultUnwillingToPerform), nil, "not-found", "Operation not implemented by server")
}

func (s *LdapServer) Start(host string, port int) {
	s.srv.ListenAndServe(host + ":" + strconv.Itoa(port))
}

func (s *LdapServer) Stop() {
	s.srv.Stop()
}

func (s *LdapServer) handleAbandon(w ldap.ResponseWriter, m *ldap.Message) {
}

func (s *LdapServer) handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	ins, logger, ctx := initRequest("bind", func(ctx zerolog.Context) zerolog.Context {
		return ctx.Int("id", m.MessageID().Int()).
			Str("authentication_choice", r.AuthenticationChoice())
	})

	if r.AuthenticationChoice() == "simple" {
		username := string(r.Name())
		password := string(r.AuthenticationSimple())
		// fmt.Println("username", username, "password", password)
		dn := s.parseDN(username)
		if dn["ou"] == nil {
			if username == s.config.BindUsername && password == s.config.BindPassword {
				writeSuccessResponse(ctx, w, ins, ldap.NewBindResponse(ldap.LDAPResultSuccess))
				return
			}
			writeErrorResponse(ctx, w, ins, ldap.NewBindResponse(ldap.LDAPResultUnwillingToPerform), nil, "missing-ou", "ou is missing in dn")
			return
		}

		organizationUnit := dn["ou"][0] // people or groups
		switch organizationUnit {
		case "people":
			uid := dn["uid"][0]
			userPasswordHashed, err := s.provider.FindUserPasswordByUsername(ctx, uid)
			if err != nil {
				writeErrorResponse(ctx, w, ins, ldap.NewBindResponse(ldap.LDAPResultInvalidCredentials), err, "user-not-found", "unable to find user: %s", uid)
				return
			}
			logger.Debug().Interface("passwordHashed", userPasswordHashed).Msg("found user during bind")
			// fmt.Println(password, user["password"])
			err = bcrypt.CompareHashAndPassword(userPasswordHashed, []byte(password))
			if err != nil {
				writeErrorResponse(ctx, w, ins, ldap.NewBindResponse(ldap.LDAPResultInvalidCredentials), err, "invalid-password", "invalid password for user: %s", uid)
				return
			}
			logger.Debug().Msg("user bind success")
			writeSuccessResponse(ctx, w, ins, ldap.NewBindResponse(ldap.LDAPResultSuccess))
			return
		case "groups":
			writeErrorResponse(ctx, w, ins, ldap.NewBindResponse(ldap.LDAPResultUnwillingToPerform), nil, "unsupported", "bind failed: groups not supported")
			return
		default:
			writeErrorResponse(ctx, w, ins, ldap.NewBindResponse(ldap.LDAPResultUnwillingToPerform), nil, "invalid-ou", "bind failed: invalid ou")
			return
		}
	} else {
		writeErrorResponse(ctx, w, ins, ldap.NewBindResponse(ldap.LDAPResultUnwillingToPerform), nil, "invalid-authentication-choice", "Authentication choice not supported")
		return
	}
}

func parseSearchFilter(filter message.Filter) map[string]string {
	condition := map[string]string{}
	switch filter := filter.(type) {
	case message.FilterAnd:
		for _, f := range filter {
			switch f := f.(type) {
			case message.FilterEqualityMatch:
				condition[string(f.AttributeDesc())] = string(f.AssertionValue())
			case message.FilterOr:
				for _, f := range f {
					switch f := f.(type) {
					case message.FilterEqualityMatch:
						condition[string(f.AttributeDesc())] = string(f.AssertionValue())
					}
				}
			}
		}
	}
	return condition
}

func (s *LdapServer) handleSearchUsers(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	ins, logger, ctx := initRequest("search-users", func(ctx zerolog.Context) zerolog.Context {
		return ctx.Int("id", m.MessageID().Int()).
			Str("base_dn", string(r.BaseObject())).
			Str("filter", r.FilterString()).
			Int("scope", r.Scope().Int())
	})

	// (&(|({username_attribute}={input})({mail_attribute}={input}))(objectClass=person))
	condition := parseSearchFilter(r.Filter())

	logger.Debug().Interface("condition", condition).Msg("search users condition")

	uid := condition["uid"]
	email := condition["email"]

	if uid == "" && email == "" {
		writeErrorResponse(ctx, w, ins, ldap.NewSearchResultDoneResponse(ldap.LDAPResultNoSuchObject), nil, "uid-email-empty", "uid and email is empty")
		return
	}
	user, err := s.provider.FindUserByUsernameOrEmail(ctx, uid, email)
	if err != nil {
		if err == provider.ErrUserNotFound {
			logger.Warn().Msg("user not found")
			writeSuccessResponse(ctx, w, ins, ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess))
			return
		}
		writeErrorResponse(ctx, w, ins, ldap.NewSearchResultDoneResponse(ldap.LDAPResultNoSuchObject), err, "provider-error", "unable to find user by uid")
		return
	}
	logger.Debug().Interface("user", user).Msg("found user during search user")
	entry := ldap.NewSearchResultEntry(fmt.Sprintf("uid=%s,ou=%s,%s", user["uid"], "people", s.config.BaseDN))
	for k, v := range user {
		entry.AddAttribute(message.AttributeDescription(k), message.AttributeValue(fmt.Sprint(v)))
	}
	entry.AddAttribute(message.AttributeDescription("objectclass"), message.AttributeValue("person"))
	entry.AddAttribute(message.AttributeDescription("ou"), message.AttributeValue("people"))
	// 	"cn":          {"alice eve smith"},
	// 	"sn":          {"smith"},
	w.Write(entry)
	writeSuccessResponse(ctx, w, ins, ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess))
}

func (s *LdapServer) handleSearchGroups(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	ins, logger, ctx := initRequest("search-groups", func(ctx zerolog.Context) zerolog.Context {
		return ctx.Int("id", m.MessageID().Int()).
			Str("base_dn", string(r.BaseObject())).
			Str("filter", r.FilterString()).
			Int("scope", r.Scope().Int())
	})

	// (&(member={dn})(objectClass=groupOfNames))
	condition := parseSearchFilter(r.Filter())

	logger.Debug().Interface("condition", condition).Msg("search groups condition")

	memberDN := condition["member"]

	if memberDN == "" {
		writeErrorResponse(ctx, w, ins, ldap.NewSearchResultDoneResponse(ldap.LDAPResultNoSuchObject), nil, "member-dn-empty", "member is empty")
		return
	}
	memberDNParsed := s.parseDN(memberDN)
	groups, err := s.provider.FindUserGroups(ctx, memberDNParsed["uid"][0])
	if err != nil {
		writeErrorResponse(ctx, w, ins, ldap.NewSearchResultDoneResponse(ldap.LDAPResultNoSuchObject), err, "provider-error", "unable to find group by uid")
		return
	}
	log.Debug().Interface("groups", groups).Msg("found user groups during search groups")
	for _, group := range groups {
		groupName := group["name"].(string)
		entry := ldap.NewSearchResultEntry(fmt.Sprintf("cn=%s,ou=%s,%s", groupName, "groups", s.config.BaseDN))
		for k, v := range group {
			entry.AddAttribute(message.AttributeDescription(k), message.AttributeValue(fmt.Sprint(v)))
		}
		entry.AddAttribute(message.AttributeDescription("objectclass"), message.AttributeValue("group"))
		entry.AddAttribute(message.AttributeDescription("ou"), message.AttributeValue("groups"))
		entry.AddAttribute(message.AttributeDescription("cn"), message.AttributeValue(groupName))

		w.Write(entry)
	}
	writeSuccessResponse(ctx, w, ins, ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess))
}

func (s *LdapServer) handleSearchDSE(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	ins, _, ctx := initRequest("search-dse", func(ctx zerolog.Context) zerolog.Context {
		return ctx.Int("id", m.MessageID().Int()).
			Str("base_dn", string(r.BaseObject())).
			Interface("filter", r.Filter()).
			Str("filterstring", r.FilterString()).
			Interface("attributes", r.Attributes()).
			Int("timelimit", r.TimeLimit().Int()).
			Int("scope", r.Scope().Int())
	})

	e := ldap.NewSearchResultEntry("")
	e.AddAttribute("vendorName", "ldap server")
	e.AddAttribute("vendorVersion", "0.0.1")
	e.AddAttribute("objectClass", "top", "extensibleObject")
	e.AddAttribute("supportedLDAPVersion", "3")
	// e.AddAttribute("namingContexts", "o=My Company, c=US")
	// e.AddAttribute("subschemaSubentry", "cn=schema")
	// e.AddAttribute("namingContexts", "ou=system", "ou=schema", "dc=example,dc=com", "ou=config")
	// e.AddAttribute("supportedFeatures", "1.3.6.1.4.1.4203.1.5.1")
	// e.AddAttribute("supportedControl", "2.16.840.1.113730.3.4.3", "1.3.6.1.4.1.4203.1.10.1", "2.16.840.1.113730.3.4.2", "1.3.6.1.4.1.4203.1.9.1.4", "1.3.6.1.4.1.42.2.27.8.5.1", "1.3.6.1.4.1.4203.1.9.1.1", "1.3.6.1.4.1.4203.1.9.1.3", "1.3.6.1.4.1.4203.1.9.1.2", "1.3.6.1.4.1.18060.0.0.1", "2.16.840.1.113730.3.4.7", "1.2.840.113556.1.4.319")
	// e.AddAttribute("supportedExtension", "1.3.6.1.4.1.1466.20036", "1.3.6.1.4.1.4203.1.11.1", "1.3.6.1.4.1.18060.0.1.5", "1.3.6.1.4.1.18060.0.1.3", "1.3.6.1.4.1.1466.20037")
	e.AddAttribute("supportedExtension", "1.3.6.1.4.1.4203.1.11.1")
	// e.AddAttribute("supportedSASLMechanisms", "NTLM", "GSSAPI", "GSS-SPNEGO", "CRAM-MD5", "SIMPLE", "DIGEST-MD5")
	// e.AddAttribute("entryUUID", "f290425c-8272-4e62-8a67-92b06f38dbf5")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	writeSuccessResponse(ctx, w, ins, res)
}

func (s *LdapServer) passwordModifyHandler(w ldap.ResponseWriter, m *ldap.Message) {
	ins, logger, ctx := initRequest("password-modify", func(ctx zerolog.Context) zerolog.Context {
		return ctx.Int("id", m.MessageID().Int())
	})
	r := m.GetExtendedRequest()

	val := r.RequestValue().Bytes()
	pkt, err := ber.DecodePacketErr(val)
	if err != nil || len(pkt.Children) != 2 {
		writeErrorResponse(ctx, w, ins, ldap.NewExtendedResponse(ldap.LDAPResultOther), err, "invalid-request", "invalid password modify request")
		return
	}
	dnStr := pkt.Children[0].Data.String()
	newPassword := pkt.Children[1].Data.String()
	log.Info().Str("dn", dnStr).Str("newPass", newPassword).Msg("password modify request")

	dn := s.parseDN(dnStr)
	if !reflect.DeepEqual(dn["dc"], s.parseDN(s.config.BaseDN)["dc"]) {
		writeErrorResponse(ctx, w, ins, ldap.NewExtendedResponse(ldap.LDAPResultInvalidDNSyntax), err, "invalid-dn", "invalid dn: %s", dn)
		return
	}

	organizationUnit := dn["ou"][0] // people or groups
	if organizationUnit != "people" {
		writeErrorResponse(ctx, w, ins, ldap.NewExtendedResponse(ldap.LDAPResultInvalidAttributeSyntax), err, "invalid-ou", "invalid ou: %s", organizationUnit)
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
	if err != nil {
		writeErrorResponse(ctx, w, ins, ldap.NewExtendedResponse(ldap.LDAPResultOperationsError), err, "bcrypt-hash-error", "failed to generate bcrypt hash")
		return
	}
	log.Info().Str("newPassword", string(newPassword)).Str("hashedPassword", string(hashedPassword)).Hex("newPasswordBytes", []byte(newPassword)).Msg("updating password")
	uid := dn["uid"][0]
	err = s.provider.UpdateUserPassword(ctx, uid, string(hashedPassword))
	if err != nil {
		writeErrorResponse(ctx, w, ins, ldap.NewExtendedResponse(ldap.LDAPResultOperationsError), err, "provider-update-error", "unable to update user password for uid: %s", uid)
		return
	}

	logger.Debug().Msg("modify success")
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	writeSuccessResponse(ctx, w, ins, res)
}

func (s *LdapServer) parseDN(dnStr string) map[string][]string {
	dnParts := strings.FieldsFunc(dnStr, func(r rune) bool {
		return r == ','
	})
	res := map[string][]string{}
	for i, part := range dnParts {
		dnParts[i] = strings.TrimSpace(part)
		pargs := strings.SplitN(part, "=", 2)
		if len(pargs) != 2 {
			continue
		}
		key, value := pargs[0], pargs[1]
		res[key] = append(res[key], value)
	}
	return res
}

func writeErrorResponse(ctx context.Context, w ldap.ResponseWriter, ins ldapInstrumentor, response message.ProtocolOp, err error, errCode string, format string, v ...interface{}) {
	ins("error", errCode)
	log.Ctx(ctx).Error().Err(err).Str("error-code", errCode).Msgf(format, v...)
	switch res := response.(type) {
	case message.ExtendedResponse:
		res.SetDiagnosticMessage(fmt.Sprintf(format, v...))
		w.Write(res)
	case message.SearchResultDone:
		w.Write(res)
	case message.BindResponse:
		res.SetDiagnosticMessage(fmt.Sprintf(format, v...))
		w.Write(res)
	case message.LDAPResult:
		res.SetDiagnosticMessage(fmt.Sprintf(format, v...))
		w.Write(res)
	default:
		log.Panic().Msgf("unsupported response type: %T", response)
	}
}

func writeSuccessResponse(ctx context.Context, w ldap.ResponseWriter, ins ldapInstrumentor, response message.ProtocolOp) {
	w.Write(response)
	ins("success", "")
	log.Ctx(ctx).Debug().Msgf("request successful")
}
