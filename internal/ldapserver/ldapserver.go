package ldapserver

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/blesswinsamuel/ldap-sql-proxy/internal/provider"
	"github.com/go-ldap/ldap"
	"github.com/jimlambrt/gldap"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	BindUsername string
	BindPassword string
	BaseDN       string
}

type LdapServer struct {
	provider provider.Provider
	srv      *gldap.Server
	config   Config

	// a very simple way to track authenticated connections
	authenticatedConnections map[int]struct{}
}

func NewLdapServer(provider provider.Provider, config Config) *LdapServer {
	s := &LdapServer{provider: provider, config: config}
	s.authenticatedConnections = make(map[int]struct{})
	var err error
	s.srv, err = gldap.NewServer()
	if err != nil {
		log.Fatal().Msgf("unable to create server: %s", err.Error())
	}
	r, err := gldap.NewMux()
	if err != nil {
		log.Fatal().Msgf("unable to create router: %s", err.Error())
	}
	r.Bind(s.bindHandler)
	r.Search(s.searchHandler)
	r.Modify(s.modifyHandler)
	r.Unbind(s.unbindHandler)
	// r.ExtendedOperation(s.passwordModifyHandler, gldap.ExtendedOperationPasswordModify)
	s.srv.Router(r)
	return s
}

func (s *LdapServer) Start(host string, port int) {
	s.srv.Run(host + ":" + strconv.Itoa(port))
}

func (s *LdapServer) Stop() {
	log.Info().Msg("stopping ldap server")
	s.srv.Stop()
	log.Info().Msg("stopped ldap server")
}

func LdapMustParseDN(v string) *ldap.DN {
	dn, err := ldap.ParseDN(v)
	if err != nil {
		panic(err)
	}
	return dn
}

func (s *LdapServer) bindHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	logger := log.With().Str("method", "bindHandler").Int("id", r.ID).Logger()
	m, err := r.GetSimpleBindMessage()
	if err != nil {
		logger.Error().Err(err).Msgf("not a simple bind message")
		w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
		return
	}
	logger = logger.With().Str("username", m.UserName).Logger()
	logger.Info().Msgf("bind request")

	dn, err := ldap.ParseDN(m.UserName)
	if err != nil {
		logger.Error().Err(err).Msgf("unable to parse dn")
		w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
		return
	}
	baseDN := LdapMustParseDN(s.config.BaseDN)
	if !baseDN.AncestorOf(dn) {
		logger.Error().Err(err).Msgf("invalid dn: %s", dn)
		w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
		return
	}
	// if dn.Equal(LdapMustParseDN("cn="+s.config.BindUsername+","+s.config.BaseDN)) {
	// }

	if m.UserName == s.config.BindUsername && m.Password == gldap.Password(s.config.BindPassword) {
		s.authenticatedConnections[r.ConnectionID()] = struct{}{} // mark connection as authenticated
		logger.Info().Msg("bind success")
		w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultSuccess)))
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
			w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(user["password"].(string)), []byte(m.Password))
		if err != nil {
			logger.Error().Err(err).Msgf("invalid password for user: %s", uid)
			w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
			return
		}
		logger.Info().Msg("user bind success")
		w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultSuccess)))
		return
	case "groups":
		logger.Info().Msg("bind failed - groups not supported")
		w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
		return
	default:
		logger.Error().Msgf("invalid ou: %s", dn)
		w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
		return
	}
}

func (s *LdapServer) unbindHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	log.Info().Msg("unbind")
	delete(s.authenticatedConnections, r.ConnectionID())
}

// https://github.com/glauth/glauth/blob/0e7769ff841e096dbf0cb67768cbd2ab7142f6fb/v2/pkg/handler/ldap.go#L62
// https://github.com/authelia/authelia/blob/ae8d25f4be3b4ff880dd847b9fa40e1c56d0ddc8/internal/authentication/ldap_user_provider.go#L240
// https://github.com/jimlambrt/gldap/blob/2ad3888755a37c65bd1fea35b347e8e7bf414f6e/testdirectory/directory.go#L129

func (s *LdapServer) searchHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	logger := log.With().Str("method", "searchHandler").Int("id", r.ID).Logger()
	// check if connection is authenticated
	if _, ok := s.authenticatedConnections[r.ConnectionID()]; !ok {
		log.Printf("connection %d is not authorized", r.ConnectionID())
		w.Write(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultAuthorizationDenied)))
		return
	}

	m, err := r.GetSearchMessage()
	if err != nil {
		logger.Printf("not a search message: %s", err)
		w.Write(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultAuthorizationDenied)))
		return
	}
	logger = logger.With().Str("base_dn", m.BaseDN).Str("filter", m.Filter).Int64("scope", int64(m.Scope)).Logger()
	logger.Info().Msg("search request")

	if m.BaseDN == "" {
		// RootDSE search
		entry := r.NewSearchResponseEntry(
			s.config.BaseDN,
		)
		logger.Info().Msg("RootDSE search success")
		w.Write(entry)
		w.Write(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess)))
		return
	}

	dn, err := ldap.ParseDN(m.BaseDN)
	if err != nil {
		logger.Error().Err(err).Msgf("unable to parse dn")
		w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
		return
	}
	baseDN := LdapMustParseDN(s.config.BaseDN)
	if !baseDN.AncestorOf(dn) {
		logger.Error().Err(err).Msgf("invalid dn: %s", dn)
		w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
		return
	}

	parsedFilter, err := ldap.CompileFilter(m.Filter)
	if err != nil {
		logger.Printf("unable to parse filter dn: %s", err)
		w.Write(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultAuthorizationDenied)))
		return
	}
	logger.Info().Interface("parsedFilter", parsedFilter).Msg("parsed filter")

	rdnsMap := rdnsToMap(dn.RDNs)
	organizationUnit := rdnsMap["ou"][0] // people or groups
	switch organizationUnit {
	case "people":
		condition := map[string]string{}
		if parsedFilter.Tag == ldap.FilterAnd {
			for _, f := range parsedFilter.Children {
				if f.Tag == ldap.FilterEqualityMatch {
					condition[f.Children[0].Data.String()] = f.Children[1].Data.String()
				}
			}
		}
		logger.Info().Interface("condition", condition).Msg("condition")

		uid := condition["uid"]

		if uid == "" {
			logger.Error().Msg("uid is empty")
			w.Write(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess)))
			// w.Write(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultAuthorizationDenied)))
			return
		}
		user, err := s.provider.FindByUID(context.Background(), uid)
		if err != nil {
			logger.Error().Msgf("unable to find user by uid: %s", err)
			w.Write(r.NewSearchDoneResponse())
			return
		}
		attributes := map[string][]string{}
		for k, v := range user {
			if k == "password" {
				continue
			}
			attributes[k] = []string{fmt.Sprint(v)}
		}
		attributes["objectclass"] = []string{"person"}
		attributes["ou"] = []string{"people"}
		entry := r.NewSearchResponseEntry(
			fmt.Sprintf("uid=%s,ou=%s,%s", uid, organizationUnit, s.config.BaseDN),
			gldap.WithAttributes(attributes),
			// gldap.WithAttributes(map[string][]string{
			// 	"cn":          {"alice eve smith"},
			// 	"givenname":   {"alice"},
			// 	"sn":          {"smith"},
			// 	"description": {"friend of Rivest, Shamir and Adleman"},
			// }),
		)
		w.Write(entry)
		w.Write(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess)))
		return
	case "groups":
		condition := map[string]string{}
		if parsedFilter.Tag == ldap.FilterAnd {
			for _, f := range parsedFilter.Children {
				if f.Tag == ldap.FilterEqualityMatch {
					condition[f.Children[0].Data.String()] = f.Children[1].Data.String()
				}
			}
		}
		logger.Info().Interface("condition", condition).Msg("condition")

		memberDN := condition["member"]

		if memberDN == "" {
			logger.Info().Msg("member is empty")
			w.Write(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess)))
			// w.Write(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultAuthorizationDenied)))
			return
		}
		memberDNParsed, err := ldap.ParseDN(memberDN)
		if err != nil {
			logger.Error().Err(err).Msgf("unable to parse dn")
			w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
			return
		}
		groups, err := s.provider.FindGroups(context.Background(), rdnsToMap(memberDNParsed.RDNs)["uid"][0])
		if err != nil {
			logger.Error().Msgf("unable to find groups by uid: %s", err)
			w.Write(r.NewSearchDoneResponse())
			return
		}
		log.Info().Interface("groups", groups).Msg("found groups")
		for _, group := range groups {
			attributes := map[string][]string{}
			attributes["objectclass"] = []string{"group"}
			attributes["ou"] = []string{"groups"}
			attributes["cn"] = []string{group["name"].(string)}
			entry := r.NewSearchResponseEntry(
				fmt.Sprintf("cn=%s,ou=%s,%s", group, organizationUnit, s.config.BaseDN),
				gldap.WithAttributes(attributes),
			)
			w.Write(entry)
		}
		w.Write(r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess)))
		return
	default:
		logger.Error().Msgf("invalid ou: %s", dn)
		w.Write(r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
		return
	}
}

func rdnsToMap(rdns []*ldap.RelativeDN) map[string][]string {
	res := map[string][]string{}
	for _, a := range rdns {
		for _, v := range a.Attributes {
			res[v.Type] = append(res[v.Type], v.Value)
		}
	}
	return res
}

func (s *LdapServer) modifyHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	logger := log.With().Str("method", "modifyHandler").Int("id", r.ID).Logger()
	// The LDAP user DN is from the configuration. By default, cn=admin,ou=people,dc=example,dc=com.
	// The LDAP password is from the configuration (same as to log in to the web UI).
	// The users are all located in ou=people, + the base DN, so by default user bob is at cn=bob,ou=people,dc=example,dc=com.
	// Similarly, the groups are located in ou=groups, so the group family will be at cn=family,ou=groups,dc=example,dc=com.

	m, err := r.GetModifyMessage()
	if err != nil {
		w.Write(r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
		logger.Printf("not a modify message: %s", err)
		return
	}
	logger = logger.With().Str("dn", m.DN).Interface("changes", m.Changes).Interface("controls", m.Controls).Logger()
	logger.Info().Msg("modify request")

	dn, err := ldap.ParseDN(m.DN)
	if err != nil {
		logger.Error().Err(err).Msgf("unable to parse dn")
		w.Write(r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
		return
	}
	baseDN := LdapMustParseDN(s.config.BaseDN)
	if !baseDN.AncestorOf(dn) {
		logger.Error().Err(err).Msgf("invalid dn: %s", dn)
		w.Write(r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
		return
	}

	rdnsMap := rdnsToMap(dn.RDNs)
	organizationUnit := rdnsMap["ou"][0] // people or groups
	switch organizationUnit {
	case "people":
		for _, change := range m.Changes {
			if change.Modification.Type == "userPassword" {
				newPassword := strings.TrimSpace(change.Modification.Vals[0])
				newPassword = strings.TrimLeftFunc(newPassword, func(r rune) bool {
					return r < 0x20
				})
				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
				if err != nil {
					logger.Error().Err(err).Msgf("failed to generate bcrypt hash")
					w.Write(r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
					return
				}
				log.Info().Str("newPassword", string(newPassword)).Str("hashedPassword", string(hashedPassword)).Hex("newPasswordBytes", []byte(newPassword)).Msg("updating password")
				uid := rdnsMap["uid"][0]
				err = s.provider.UpdateUserPassword(context.Background(), uid, string(hashedPassword))
				if err != nil {
					logger.Error().Err(err).Msgf("unable to update user password: %s", uid)
					w.Write(r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
					return
				}
				logger.Info().Msg("modify success")
				w.Write(r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultSuccess)))
				return
			}
		}
		logger.Info().Msg("modify failed - userPassword not found")
		w.Write(r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
		return
	case "groups":
		logger.Info().Msg("modify failed - groups not supported")
		w.Write(r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
		return
	default:
		logger.Error().Msgf("invalid ou: %s", dn)
		w.Write(r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials)))
		return
	}
}
