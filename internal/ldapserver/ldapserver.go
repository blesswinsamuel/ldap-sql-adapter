package ldapserver

import (
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"

	stdlog "log"

	"github.com/blesswinsamuel/ldap-sql-proxy/internal/provider"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/lor00x/goldap/message"
	"github.com/rs/zerolog/log"

	ldap "github.com/vjeantet/ldapserver"
	"golang.org/x/crypto/bcrypt"
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

func (s *LdapServer) handleNotFound(w ldap.ResponseWriter, r *ldap.Message) {
	logger := log.With().
		Str("method", "handleNotFound").
		Logger()
	logger.Warn().Msg("not found request")

	res := ldap.NewResponse(ldap.LDAPResultUnwillingToPerform)
	res.SetDiagnosticMessage("Operation not implemented by server")
	w.Write(res)
}

func (s *LdapServer) Start(host string, port int) {
	s.srv.ListenAndServe(host + ":" + strconv.Itoa(port))
}

func (s *LdapServer) Stop() {
	log.Info().Msg("stopping ldap server")
	s.srv.Stop()
	log.Info().Msg("stopped ldap server")
}

func (s *LdapServer) handleAbandon(w ldap.ResponseWriter, m *ldap.Message) {
}

func (s *LdapServer) handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	logger := log.With().Str("method", "handleBind").Int("id", m.MessageID().Int()).Logger()
	ctx := logger.WithContext(context.Background())
	r := m.GetBindRequest()
	logger.Debug().Msgf("bind request")
	if r.AuthenticationChoice() == "simple" {
		username := string(r.Name())
		password := string(r.AuthenticationSimple())
		logger = logger.With().Str("username", username).Str("password", password).Logger()
		dn := s.parseDN(username)
		logger.Debug().Msgf("simple bind request")
		if dn["ou"] == nil {
			if username == s.config.BindUsername && password == s.config.BindPassword {
				// s.authenticatedConnections[r.ConnectionID()] = struct{}{} // mark connection as authenticated
				logger.Debug().Msg("bind success")
				w.Write(ldap.NewBindResponse(ldap.LDAPResultSuccess))
				return
			}
			errorResponse(ctx, w, ldap.NewBindResponse(ldap.LDAPResultUnwillingToPerform), nil, "ou is missing in dn")
			return
		}

		organizationUnit := dn["ou"][0] // people or groups
		switch organizationUnit {
		case "people":
			uid := dn["uid"][0]
			user, err := s.provider.FindByUID(ctx, uid)
			if err != nil {
				errorResponse(ctx, w, ldap.NewBindResponse(ldap.LDAPResultInvalidCredentials), err, "unable to find user: %s", uid)
				return
			}
			err = bcrypt.CompareHashAndPassword([]byte(user["password"].(string)), []byte(password))
			if err != nil {
				errorResponse(ctx, w, ldap.NewBindResponse(ldap.LDAPResultInvalidCredentials), err, "invalid password for user: %s", uid)
				return
			}
			logger.Debug().Msg("user bind success")
			w.Write(ldap.NewBindResponse(ldap.LDAPResultSuccess))
			return
		case "groups":
			errorResponse(ctx, w, ldap.NewBindResponse(ldap.LDAPResultUnwillingToPerform), nil, "bind failed: groups not supported")
			return
		default:
			errorResponse(ctx, w, ldap.NewBindResponse(ldap.LDAPResultUnwillingToPerform), nil, "bind failed: invalid ou")
			return
		}
	} else {
		errorResponse(ctx, w, ldap.NewBindResponse(ldap.LDAPResultUnwillingToPerform), nil, "Authentication choice not supported")
		return
	}
}

func (s *LdapServer) handleSearchUsers(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	logger := log.With().Str("method", "handleSearchUsers").
		Int("id", m.MessageID().Int()).
		Str("base_dn", string(r.BaseObject())).Str("filter", r.FilterString()).Int("scope", r.Scope().Int()).
		Logger()
	ctx := logger.WithContext(context.Background())
	logger.Debug().Msg("search users request")

	condition := map[string]string{}
	switch filter := r.Filter().(type) {
	case message.FilterAnd:
		for _, f := range filter {
			switch f := f.(type) {
			case message.FilterEqualityMatch:
				condition[string(f.AttributeDesc())] = string(f.AssertionValue())
			}
		}
	}

	logger.Info().Interface("condition", condition).Msg("condition")

	uid := condition["uid"]

	if uid == "" {
		errorResponse(ctx, w, ldap.NewSearchResultDoneResponse(ldap.LDAPResultNoSuchObject), nil, "uid is empty")
		return
	}
	user, err := s.provider.FindByUID(ctx, uid)
	if err != nil {
		if err.Error() == "user not found" {
			logger.Warn().Msg("user not found")
			w.Write(ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess))
			return
		}
		errorResponse(ctx, w, ldap.NewSearchResultDoneResponse(ldap.LDAPResultNoSuchObject), err, "unable to find user by uid")
		return
	}
	entry := ldap.NewSearchResultEntry(fmt.Sprintf("uid=%s,ou=%s,%s", uid, "people", s.config.BaseDN))
	for k, v := range user {
		if k == "password" {
			continue
		}
		entry.AddAttribute(message.AttributeDescription(k), message.AttributeValue(fmt.Sprint(v)))
	}
	entry.AddAttribute(message.AttributeDescription("objectclass"), message.AttributeValue("person"))
	entry.AddAttribute(message.AttributeDescription("ou"), message.AttributeValue("people"))
	w.Write(entry)

	// 	ldap.WithAttributes(attributes),
	// 	// ldap.WithAttributes(map[string][]string{
	// 	// 	"cn":          {"alice eve smith"},
	// 	// 	"givenname":   {"alice"},
	// 	// 	"sn":          {"smith"},
	// 	// 	"description": {"friend of Rivest, Shamir and Adleman"},
	// 	// }),
	// )
	w.Write(ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess))
}

func (s *LdapServer) handleSearchGroups(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	logger := log.With().Str("method", "handleSearchGroups").
		Int("id", m.MessageID().Int()).
		Str("base_dn", string(r.BaseObject())).Str("filter", r.FilterString()).Int("scope", r.Scope().Int()).
		Logger()
	ctx := logger.WithContext(context.Background())
	logger.Debug().Msg("search groups request")

	condition := map[string]string{}
	switch filter := r.Filter().(type) {
	case message.FilterAnd:
		for _, f := range filter {
			switch f := f.(type) {
			case message.FilterEqualityMatch:
				condition[string(f.AttributeDesc())] = string(f.AssertionValue())
			}
		}
	}

	logger.Info().Interface("condition", condition).Msg("condition")

	memberDN := condition["member"]

	if memberDN == "" {
		errorResponse(ctx, w, ldap.NewSearchResultDoneResponse(ldap.LDAPResultNoSuchObject), nil, "member is empty")
		return
	}
	memberDNParsed := s.parseDN(memberDN)
	groups, err := s.provider.FindGroups(ctx, memberDNParsed["uid"][0])
	if err != nil {
		errorResponse(ctx, w, ldap.NewSearchResultDoneResponse(ldap.LDAPResultNoSuchObject), err, "unable to find group by uid")
		return
	}
	log.Info().Interface("groups", groups).Msg("found groups")
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
	w.Write(ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess))
}

func (s *LdapServer) handleSearchDSE(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	logger := log.With().
		Str("method", "handleSearchDSE").
		Int("id", m.MessageID().Int()).
		Str("basedn", string(r.BaseObject())).
		Interface("filter", r.Filter()).
		Interface("filterstring", r.FilterString()).
		Interface("attributes", r.Attributes()).
		Int("timelimit", r.TimeLimit().Int()).
		Logger()
	logger.Debug().Msg("searchDSE request")

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
	w.Write(res)
}

func (s *LdapServer) passwordModifyHandler(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetExtendedRequest()
	logger := log.With().
		Str("method", "passwordModifyHandler").
		Int("id", m.MessageID().Int()).
		Logger()
	ctx := logger.WithContext(context.Background())
	logger.Debug().Msg("passwordModify request")

	val := r.RequestValue().Bytes()
	pkt, err := ber.DecodePacketErr(val)
	if err != nil || len(pkt.Children) != 2 {
		errorResponse(ctx, w, ldap.NewExtendedResponse(ldap.LDAPResultOther), err, "invalid password modify request")
		return
	}
	dnStr := pkt.Children[0].Data.String()
	newPassword := pkt.Children[1].Data.String()
	log.Info().Str("dn", dnStr).Str("newPass", newPassword).Msg("password modify request")

	dn := s.parseDN(dnStr)
	if !reflect.DeepEqual(dn["dc"], s.parseDN(s.config.BaseDN)["dc"]) {
		errorResponse(ctx, w, ldap.NewExtendedResponse(ldap.LDAPResultInvalidDNSyntax), err, "invalid dn: %s", dn)
		return
	}

	organizationUnit := dn["ou"][0] // people or groups
	if organizationUnit != "people" {
		errorResponse(ctx, w, ldap.NewExtendedResponse(ldap.LDAPResultInvalidAttributeSyntax), err, "invalid ou: %s", organizationUnit)
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
	if err != nil {
		errorResponse(ctx, w, ldap.NewExtendedResponse(ldap.LDAPResultOperationsError), err, "failed to generate bcrypt hash")
		return
	}
	log.Info().Str("newPassword", string(newPassword)).Str("hashedPassword", string(hashedPassword)).Hex("newPasswordBytes", []byte(newPassword)).Msg("updating password")
	uid := dn["uid"][0]
	err = s.provider.UpdateUserPassword(ctx, uid, string(hashedPassword))
	if err != nil {
		errorResponse(ctx, w, ldap.NewExtendedResponse(ldap.LDAPResultOperationsError), err, "unable to update user password for uid: %s", uid)
		return
	}

	logger.Debug().Msg("modify success")
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
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

func errorResponse(ctx context.Context, w ldap.ResponseWriter, response message.ProtocolOp, err error, format string, v ...interface{}) {
	log.Ctx(ctx).Error().Err(err).Msgf(format, v...)
	switch res := response.(type) {
	case message.ExtendedResponse:
		res.SetDiagnosticMessage(fmt.Sprintf(format, v...))
		w.Write(res)
	case message.SearchResultDone:
		w.Write(res)
	case message.BindResponse:
		res.SetDiagnosticMessage(fmt.Sprintf(format, v...))
		w.Write(res)
	}
}
