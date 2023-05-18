package ldapserver

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	stdlog "log"

	"github.com/blesswinsamuel/ldap-sql-proxy/internal/provider"
	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap"
	"github.com/lor00x/goldap/message"
	"github.com/rs/zerolog/log"

	ldap "github.com/MDM23/ldapserver"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	BindUsername string
	BindPassword string
	BaseDN       string
}

type LdapServer struct {
	provider provider.Provider
	srv      *ldap.Server
	config   Config

	// a very simple way to track authenticated connections
	authenticatedConnections map[int]struct{}
}

func NewLdapServer(provider provider.Provider, config Config) *LdapServer {
	s := &LdapServer{provider: provider, config: config}
	s.authenticatedConnections = make(map[int]struct{})
	ldap.Logger = stdlog.New(os.Stdout, "[ldap] ", stdlog.LstdFlags)
	ldap.Logger.(*stdlog.Logger).SetOutput(ioutil.Discard)
	var err error
	s.srv = ldap.NewServer()
	if err != nil {
		log.Fatal().Msgf("unable to create server: %s", err.Error())
	}
	routes := ldap.NewRouteMux()
	// routes.NotFound(handleNotFound)
	// routes.Abandon(handleAbandon)
	routes.Bind(s.handleBind)
	// routes.Compare(handleCompare)
	// routes.Add(handleAdd)
	// routes.Delete(handleDelete)
	// routes.Modify(s.handleModify)
	routes.Search(s.handleSearchDSE).
		BaseDn("").
		Scope(ldap.SearchRequestScopeBaseObject).
		Filter("(objectclass=*)").
		Label("Search - ROOT DSE")
	routes.Search(s.handleSearchUsers).
		BaseDn("ou=people," + config.BaseDN).
		// Scope(ldap.SearchRequestScopeBaseObject).
		Scope(ldap.SearchRequestHomeSubtree).
		Label("Search - People")
	routes.Search(s.handleSearchGroups).
		BaseDn("ou=groups," + config.BaseDN).
		// Scope(ldap.SearchRequestScopeBaseObject).
		Scope(ldap.SearchRequestHomeSubtree).
		Label("Search - Groups")
	// routes.Search(s.handleSearch).Label("Search - Generic")
	routes.NotFound(s.handleNotFound)

	routes.Extended(s.passwordModifyHandler).
		RequestName(ldap.NoticeOfPasswordModify).Label("Ext - PasswordModify")

	// r.Unbind(s.handleUnbind)
	s.srv.Handle(routes)
	return s
}

func (s *LdapServer) handleNotFound(w ldap.ResponseWriter, r *ldap.Message) {
	// switch r.ProtocolOpType() {
	// case ldap.ApplicationBindRequest:
	// 	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	// 	res.SetDiagnosticMessage("Default binding behavior set to return Success")

	// 	w.Write(res)

	// default:
	logger := log.With().
		Str("method", "handleNotFound").
		Logger()
	logger.Warn().Msg("not found request")

	res := ldap.NewResponse(ldap.LDAPResultUnwillingToPerform)
	res.SetDiagnosticMessage("Operation not implemented by server")
	w.Write(res)
	// }
}

func (s *LdapServer) Start(host string, port int) {
	s.srv.ListenAndServe(host + ":" + strconv.Itoa(port))
}

func (s *LdapServer) Stop() {
	log.Info().Msg("stopping ldap server")
	s.srv.Stop()
	log.Info().Msg("stopped ldap server")
}

func LdapMustParseDN(v string) *goldap.DN {
	dn, err := goldap.ParseDN(v)
	if err != nil {
		panic(err)
	}
	return dn
}

func (s *LdapServer) handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	logger := log.With().Str("method", "handleBind").Int("id", m.MessageID().Int()).Logger()
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	logger.Info().Msgf("bind request")
	if r.AuthenticationChoice() == "simple" {
		username := string(r.Name())
		password := string(r.AuthenticationSimple())
		logger = logger.With().Str("username", username).Str("password", password).Logger()
		dn, err := goldap.ParseDN(username)
		if err != nil {
			logger.Error().Err(err).Msgf("unable to parse dn")
			res.SetResultCode(ldap.LDAPResultInvalidCredentials)
			res.SetDiagnosticMessage("invalid dn")
			w.Write(res)
			return
		}
		baseDN := LdapMustParseDN(s.config.BaseDN)
		if !baseDN.AncestorOf(dn) {
			logger.Error().Err(err).Msgf("base dn does not match")
			res.SetResultCode(ldap.LDAPResultInvalidCredentials)
			res.SetDiagnosticMessage("invalid dn")
			w.Write(res)
			return
		}
		if username == s.config.BindUsername && password == s.config.BindPassword {
			// s.authenticatedConnections[r.ConnectionID()] = struct{}{} // mark connection as authenticated
			logger.Info().Msg("bind success")
			w.Write(res)
			return
		}

		rdnsMap := rdnsToMap(dn.RDNs)
		organizationUnit := rdnsMap["ou"][0] // people or groups
		switch organizationUnit {
		case "people":
			uid := rdnsMap["uid"][0]
			user, err := s.provider.FindByUID(context.Background(), uid)
			if err != nil {
				logger.Error().Err(err).Msgf("unable to find user: %s", uid)
				res.SetResultCode(ldap.LDAPResultInvalidCredentials)
				res.SetDiagnosticMessage("unable to find user")
				w.Write(res)
				return
			}
			err = bcrypt.CompareHashAndPassword([]byte(user["password"].(string)), []byte(password))
			if err != nil {
				logger.Error().Err(err).Msgf("invalid password for user: %s", uid)
				res.SetResultCode(ldap.LDAPResultInvalidCredentials)
				res.SetDiagnosticMessage("invalid password for user")
				w.Write(res)
				return
			}
			logger.Info().Msg("user bind success")
			w.Write(res)
			return
		case "groups":
			logger.Info().Msg("bind failed - groups not supported")
			res.SetResultCode(ldap.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage("groups not supported")
			w.Write(res)
			return
		default:
			logger.Error().Msgf("invalid ou: %s", dn)
			res.SetResultCode(ldap.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage("invalid ou")
			w.Write(res)
			return
		}
	} else {
		res.SetResultCode(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Authentication choice not supported")
		logger.Error().Msgf("Authentication choice not supported")
		w.Write(res)
		return
	}
}

// func (s *LdapServer) handleUnbind(w ldap.ResponseWriter, m *ldap.Message) {
// 	log.Info().Msg("unbind")
// 	delete(s.authenticatedConnections, r.ConnectionID())
// }

// // https://github.com/glauth/glauth/blob/0e7769ff841e096dbf0cb67768cbd2ab7142f6fb/v2/pkg/handler/ldap.go#L62
// // https://github.com/authelia/authelia/blob/ae8d25f4be3b4ff880dd847b9fa40e1c56d0ddc8/internal/authentication/ldap_user_provider.go#L240
// // https://github.com/jimlambrt/ldap/blob/2ad3888755a37c65bd1fea35b347e8e7bf414f6e/testdirectory/directory.go#L129

func (s *LdapServer) handleSearchUsers(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	r := m.GetSearchRequest()
	logger := log.With().Str("method", "handleSearchUsers").
		Int("id", m.MessageID().Int()).
		Str("base_dn", string(r.BaseObject())).Str("filter", r.FilterString()).Int("scope", r.Scope().Int()).
		Logger()
	logger.Info().Msg("search users request")
	// parsedFilter, err := goldap.CompileFilter(r.FilterString())
	// if err != nil {
	// 	logger.Printf("unable to parse filter dn: %s", err)
	// 	res.SetResultCode(ldap.LDAPResultInvalidAttributeSyntax)
	// 	w.Write(r.NewSearchDoneResponse(ldap.WithResponseCode(ldap.ResultAuthorizationDenied)))
	// 	return
	// }
	// logger.Info().Interface("parsedFilter", parsedFilter).Msg("parsed filter")

	// baseDN := r.BaseObject()
	// dn, err := goldap.ParseDN(string(baseDN))
	// if err != nil {
	// 	logger.Error().Err(err).Msgf("unable to parse dn")
	// 	w.Write(r.NewBindResponse(ldap.WithResponseCode(ldap.ResultInvalidCredentials)))
	// 	return
	// }

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

	// // rdnsMap := rdnsToMap(dn.RDNs)
	// if parsedFilter.Tag == goldap.FilterAnd {
	// 	for _, f := range parsedFilter.Children {
	// 		if f.Tag == goldap.FilterEqualityMatch {
	// 			condition[f.Children[0].Data.String()] = f.Children[1].Data.String()
	// 		}
	// 	}
	// }
	logger.Info().Interface("condition", condition).Msg("condition")

	uid := condition["uid"]

	if uid == "" {
		logger.Error().Msg("uid is empty")
		res.SetResultCode(ldap.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}
	user, err := s.provider.FindByUID(context.Background(), uid)
	if err != nil {
		logger.Error().Msgf("unable to find user by uid: %s", err)
		res.SetResultCode(ldap.LDAPResultNoSuchObject)
		w.Write(res)
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

	// 	ldap.WithAttributes(attributes),
	// 	// ldap.WithAttributes(map[string][]string{
	// 	// 	"cn":          {"alice eve smith"},
	// 	// 	"givenname":   {"alice"},
	// 	// 	"sn":          {"smith"},
	// 	// 	"description": {"friend of Rivest, Shamir and Adleman"},
	// 	// }),
	// )
	w.Write(entry)
	w.Write(res)
}

func (s *LdapServer) handleSearchGroups(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	r := m.GetSearchRequest()
	baseDN := r.BaseObject()
	logger := log.With().Str("method", "handleSearchGroups").
		Int("id", m.MessageID().Int()).
		Str("base_dn", string(baseDN)).Str("filter", r.FilterString()).Int("scope", r.Scope().Int()).
		Logger()
	logger.Info().Msg("search groups request")
	w.Write(res)
}

func (s *LdapServer) handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	baseDN := r.BaseObject()
	logger := log.With().Str("method", "handleSearch").
		Int("id", m.MessageID().Int()).
		Str("base_dn", string(baseDN)).Str("filter", r.FilterString()).Int("scope", r.Scope().Int()).
		Logger()
	logger.Info().Msg("search request")
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

// func (s *LdapServer) handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
// 	dn, err := ldap.ParseDN(m.BaseDN)
// 	if err != nil {
// 		logger.Error().Err(err).Msgf("unable to parse dn")
// 		w.Write(r.NewBindResponse(ldap.WithResponseCode(ldap.ResultInvalidCredentials)))
// 		return
// 	}
// 	baseDN := LdapMustParseDN(s.config.BaseDN)
// 	if !baseDN.AncestorOf(dn) {
// 		logger.Error().Err(err).Msgf("invalid dn: %s", dn)
// 		w.Write(r.NewBindResponse(ldap.WithResponseCode(ldap.ResultInvalidCredentials)))
// 		return
// 	}

// 	parsedFilter, err := ldap.CompileFilter(m.Filter)
// 	if err != nil {
// 		logger.Printf("unable to parse filter dn: %s", err)
// 		w.Write(r.NewSearchDoneResponse(ldap.WithResponseCode(ldap.ResultAuthorizationDenied)))
// 		return
// 	}
// 	logger.Info().Interface("parsedFilter", parsedFilter).Msg("parsed filter")

// 	rdnsMap := rdnsToMap(dn.RDNs)
// 	organizationUnit := rdnsMap["ou"][0] // people or groups
// 	switch organizationUnit {
// 	case "people":
// 		condition := map[string]string{}
// 		if parsedFilter.Tag == ldap.FilterAnd {
// 			for _, f := range parsedFilter.Children {
// 				if f.Tag == ldap.FilterEqualityMatch {
// 					condition[f.Children[0].Data.String()] = f.Children[1].Data.String()
// 				}
// 			}
// 		}
// 		logger.Info().Interface("condition", condition).Msg("condition")

// 		uid := condition["uid"]

// 		if uid == "" {
// 			logger.Error().Msg("uid is empty")
// 			w.Write(r.NewSearchDoneResponse(ldap.WithResponseCode(ldap.ResultSuccess)))
// 			// w.Write(r.NewSearchDoneResponse(ldap.WithResponseCode(ldap.ResultAuthorizationDenied)))
// 			return
// 		}
// 		user, err := s.provider.FindByUID(context.Background(), uid)
// 		if err != nil {
// 			logger.Error().Msgf("unable to find user by uid: %s", err)
// 			w.Write(r.NewSearchDoneResponse())
// 			return
// 		}
// 		attributes := map[string][]string{}
// 		for k, v := range user {
// 			if k == "password" {
// 				continue
// 			}
// 			attributes[k] = []string{fmt.Sprint(v)}
// 		}
// 		attributes["objectclass"] = []string{"person"}
// 		attributes["ou"] = []string{"people"}
// 		entry := r.NewSearchResponseEntry(
// 			fmt.Sprintf("uid=%s,ou=%s,%s", uid, organizationUnit, s.config.BaseDN),
// 			ldap.WithAttributes(attributes),
// 			// ldap.WithAttributes(map[string][]string{
// 			// 	"cn":          {"alice eve smith"},
// 			// 	"givenname":   {"alice"},
// 			// 	"sn":          {"smith"},
// 			// 	"description": {"friend of Rivest, Shamir and Adleman"},
// 			// }),
// 		)
// 		w.Write(entry)
// 		w.Write(r.NewSearchDoneResponse(ldap.WithResponseCode(ldap.ResultSuccess)))
// 		return
// 	case "groups":
// 		condition := map[string]string{}
// 		if parsedFilter.Tag == ldap.FilterAnd {
// 			for _, f := range parsedFilter.Children {
// 				if f.Tag == ldap.FilterEqualityMatch {
// 					condition[f.Children[0].Data.String()] = f.Children[1].Data.String()
// 				}
// 			}
// 		}
// 		logger.Info().Interface("condition", condition).Msg("condition")

// 		memberDN := condition["member"]

// 		if memberDN == "" {
// 			logger.Info().Msg("member is empty")
// 			w.Write(r.NewSearchDoneResponse(ldap.WithResponseCode(ldap.ResultSuccess)))
// 			// w.Write(r.NewSearchDoneResponse(ldap.WithResponseCode(ldap.ResultAuthorizationDenied)))
// 			return
// 		}
// 		memberDNParsed, err := ldap.ParseDN(memberDN)
// 		if err != nil {
// 			logger.Error().Err(err).Msgf("unable to parse dn")
// 			w.Write(r.NewBindResponse(ldap.WithResponseCode(ldap.ResultInvalidCredentials)))
// 			return
// 		}
// 		groups, err := s.provider.FindGroups(context.Background(), rdnsToMap(memberDNParsed.RDNs)["uid"][0])
// 		if err != nil {
// 			logger.Error().Msgf("unable to find groups by uid: %s", err)
// 			w.Write(r.NewSearchDoneResponse())
// 			return
// 		}
// 		log.Info().Interface("groups", groups).Msg("found groups")
// 		for _, group := range groups {
// 			attributes := map[string][]string{}
// 			attributes["objectclass"] = []string{"group"}
// 			attributes["ou"] = []string{"groups"}
// 			attributes["cn"] = []string{group["name"].(string)}
// 			entry := r.NewSearchResponseEntry(
// 				fmt.Sprintf("cn=%s,ou=%s,%s", group, organizationUnit, s.config.BaseDN),
// 				ldap.WithAttributes(attributes),
// 			)
// 			w.Write(entry)
// 		}
// 		w.Write(r.NewSearchDoneResponse(ldap.WithResponseCode(ldap.ResultSuccess)))
// 		return
// 	default:
// 		logger.Error().Msgf("invalid ou: %s", dn)
// 		w.Write(r.NewBindResponse(ldap.WithResponseCode(ldap.ResultInvalidCredentials)))
// 		return
// 	}
// }

func rdnsToMap(rdns []*goldap.RelativeDN) map[string][]string {
	res := map[string][]string{}
	for _, a := range rdns {
		for _, v := range a.Attributes {
			res[v.Type] = append(res[v.Type], v.Value)
		}
	}
	return res
}

// func (s *LdapServer) handleModify(w ldap.ResponseWriter, m *ldap.Message) {
// 	logger := log.With().Str("method", "handleModify").Int("id", r.ID).Logger()
// 	// The LDAP user DN is from the configuration. By default, cn=admin,ou=people,dc=example,dc=com.
// 	// The LDAP password is from the configuration (same as to log in to the web UI).
// 	// The users are all located in ou=people, + the base DN, so by default user bob is at cn=bob,ou=people,dc=example,dc=com.
// 	// Similarly, the groups are located in ou=groups, so the group family will be at cn=family,ou=groups,dc=example,dc=com.

// 	m, err := r.GetModifyMessage()
// 	if err != nil {
// 		w.Write(r.NewModifyResponse(ldap.WithResponseCode(ldap.ResultInvalidCredentials)))
// 		logger.Printf("not a modify message: %s", err)
// 		return
// 	}
// 	logger = logger.With().Str("dn", m.DN).Interface("changes", m.Changes).Interface("controls", m.Controls).Logger()
// 	logger.Info().Msg("modify request")

// 	dn, err := ldap.ParseDN(m.DN)
// 	if err != nil {
// 		logger.Error().Err(err).Msgf("unable to parse dn")
// 		w.Write(r.NewModifyResponse(ldap.WithResponseCode(ldap.ResultInvalidCredentials)))
// 		return
// 	}
// 	baseDN := LdapMustParseDN(s.config.BaseDN)
// 	if !baseDN.AncestorOf(dn) {
// 		logger.Error().Err(err).Msgf("invalid dn: %s", dn)
// 		w.Write(r.NewModifyResponse(ldap.WithResponseCode(ldap.ResultInvalidCredentials)))
// 		return
// 	}

// 	rdnsMap := rdnsToMap(dn.RDNs)
// 	organizationUnit := rdnsMap["ou"][0] // people or groups
// 	switch organizationUnit {
// 	case "people":
// 		for _, change := range m.Changes {
// 			if change.Modification.Type == "userPassword" {
// 				newPassword := strings.TrimSpace(change.Modification.Vals[0])
// 				newPassword = strings.TrimLeftFunc(newPassword, func(r rune) bool {
// 					return r < 0x20
// 				})
// 				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
// 				if err != nil {
// 					logger.Error().Err(err).Msgf("failed to generate bcrypt hash")
// 					w.Write(r.NewModifyResponse(ldap.WithResponseCode(ldap.ResultInvalidCredentials)))
// 					return
// 				}
// 				log.Info().Str("newPassword", string(newPassword)).Str("hashedPassword", string(hashedPassword)).Hex("newPasswordBytes", []byte(newPassword)).Msg("updating password")
// 				uid := rdnsMap["uid"][0]
// 				err = s.provider.UpdateUserPassword(context.Background(), uid, string(hashedPassword))
// 				if err != nil {
// 					logger.Error().Err(err).Msgf("unable to update user password: %s", uid)
// 					w.Write(r.NewModifyResponse(ldap.WithResponseCode(ldap.ResultInvalidCredentials)))
// 					return
// 				}
// 				logger.Info().Msg("modify success")
// 				w.Write(r.NewModifyResponse(ldap.WithResponseCode(ldap.ResultSuccess)))
// 				return
// 			}
// 		}
// 		logger.Info().Msg("modify failed - userPassword not found")
// 		w.Write(r.NewModifyResponse(ldap.WithResponseCode(ldap.ResultInvalidCredentials)))
// 		return
// 	case "groups":
// 		logger.Info().Msg("modify failed - groups not supported")
// 		w.Write(r.NewModifyResponse(ldap.WithResponseCode(ldap.ResultInvalidCredentials)))
// 		return
// 	default:
// 		logger.Error().Msgf("invalid ou: %s", dn)
// 		w.Write(r.NewModifyResponse(ldap.WithResponseCode(ldap.ResultInvalidCredentials)))
// 		return
// 	}
// }

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
	logger.Info().Msg("searchDSE request")

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
	logger.Info().Msg("passwordModify request")

	val := r.RequestValue().Bytes()
	pkt, err := ber.DecodePacketErr(val)
	if err != nil || len(pkt.Children) != 2 {
		res := ldap.NewExtendedResponse(ldap.LDAPResultOther)
		w.Write(res)
		return
	}
	dn := pkt.Children[0].Data.String()
	newPassword := pkt.Children[1].Data.String()
	log.Info().Str("dn", dn).Str("newPass", newPassword).Msg("password modify request")

	dnParsed, err := goldap.ParseDN(dn)
	if err != nil {
		logger.Error().Err(err).Msgf("unable to parse dn")
		w.Write(ldap.NewExtendedResponse(ldap.LDAPResultInvalidDNSyntax))
		return
	}
	baseDN := LdapMustParseDN(s.config.BaseDN)
	if !baseDN.AncestorOf(dnParsed) {
		logger.Error().Err(err).Msgf("invalid dn: %s", dn)
		w.Write(ldap.NewExtendedResponse(ldap.LDAPResultInvalidDNSyntax))
		return
	}

	rdnsMap := rdnsToMap(dnParsed.RDNs)
	organizationUnit := rdnsMap["ou"][0] // people or groups
	if organizationUnit != "people" {
		logger.Error().Err(err).Msgf("invalid ou: %s", dn)
		w.Write(ldap.NewExtendedResponse(ldap.LDAPResultInvalidDNSyntax))
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
	if err != nil {
		logger.Error().Err(err).Msgf("failed to generate bcrypt hash")
		w.Write(ldap.NewExtendedResponse(ldap.LDAPResultOperationsError))
		return
	}
	log.Info().Str("newPassword", string(newPassword)).Str("hashedPassword", string(hashedPassword)).Hex("newPasswordBytes", []byte(newPassword)).Msg("updating password")
	uid := rdnsMap["uid"][0]
	err = s.provider.UpdateUserPassword(context.Background(), uid, string(hashedPassword))
	if err != nil {
		logger.Error().Err(err).Msgf("unable to update user password: %s", uid)
		w.Write(ldap.NewExtendedResponse(ldap.LDAPResultOperationsError))
		return
	}

	logger.Info().Msg("modify success")
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
