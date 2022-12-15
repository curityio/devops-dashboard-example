--
-- PostgreSQL database dump
--

-- Dumped from database version 14.5 (Debian 14.5-2.pgdg110+2)
-- Dumped by pg_dump version 14.5 (Debian 14.5-2.pgdg110+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: accounts; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.accounts (
    account_id character varying(64) DEFAULT public.uuid_generate_v1() NOT NULL,
    username character varying(64) NOT NULL,
    password character varying(128),
    email character varying(64),
    phone character varying(32),
    attributes jsonb,
    active smallint DEFAULT 0 NOT NULL,
    created bigint NOT NULL,
    updated bigint NOT NULL
);


ALTER TABLE public.accounts OWNER TO postgres;

--
-- Name: COLUMN accounts.account_id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.accounts.account_id IS 'Account id, or username, of this account. Unique.';


--
-- Name: COLUMN accounts.password; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.accounts.password IS 'The hashed password. Optional';


--
-- Name: COLUMN accounts.email; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.accounts.email IS 'The associated email address. Optional';


--
-- Name: COLUMN accounts.phone; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.accounts.phone IS 'The phone number of the account owner. Optional';


--
-- Name: COLUMN accounts.attributes; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.accounts.attributes IS 'Key/value map of additional attributes associated with the account.';


--
-- Name: COLUMN accounts.active; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.accounts.active IS 'Indicates if this account has been activated or not. Activation is usually via email or sms.';


--
-- Name: COLUMN accounts.created; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.accounts.created IS 'Time since epoch of account creation, in seconds';


--
-- Name: COLUMN accounts.updated; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.accounts.updated IS 'Time since epoch of latest account update, in seconds';


--
-- Name: audit; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.audit (
    id character varying(64) NOT NULL,
    instant timestamp without time zone NOT NULL,
    event_instant character varying(64) NOT NULL,
    server character varying(255) NOT NULL,
    message text NOT NULL,
    event_type character varying(48) NOT NULL,
    subject character varying(128),
    client character varying(128),
    resource character varying(128),
    authenticated_subject character varying(128),
    authenticated_client character varying(128),
    acr character varying(128),
    endpoint character varying(255),
    session character varying(128)
);


ALTER TABLE public.audit OWNER TO postgres;

--
-- Name: COLUMN audit.id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.audit.id IS 'Unique ID of the log message';


--
-- Name: COLUMN audit.instant; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.audit.instant IS 'Moment that the event was logged';


--
-- Name: COLUMN audit.event_instant; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.audit.event_instant IS 'Moment that the event occurred';


--
-- Name: COLUMN audit.server; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.audit.server IS 'The server node where the event occurred';


--
-- Name: COLUMN audit.message; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.audit.message IS 'Message describing the event';


--
-- Name: COLUMN audit.event_type; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.audit.event_type IS 'Type of event that the message is about';


--
-- Name: COLUMN audit.subject; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.audit.subject IS 'The subject (i.e., user) effected by the event';


--
-- Name: COLUMN audit.client; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.audit.client IS 'The client ID effected by the event';


--
-- Name: COLUMN audit.resource; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.audit.resource IS 'The resource ID effected by the event';


--
-- Name: COLUMN audit.authenticated_subject; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.audit.authenticated_subject IS 'The authenticated subject (i.e., user) effected by the event';


--
-- Name: COLUMN audit.authenticated_client; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.audit.authenticated_client IS 'The authenticated client effected by the event';


--
-- Name: COLUMN audit.acr; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.audit.acr IS 'The ACR used to authenticate the subject (i.e., user)';


--
-- Name: COLUMN audit.endpoint; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.audit.endpoint IS 'The endpoint where the event was triggered';


--
-- Name: COLUMN audit.session; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.audit.session IS 'The session ID in which the event was triggered';


--
-- Name: buckets; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.buckets (
    subject character varying(128) NOT NULL,
    purpose character varying(64) NOT NULL,
    attributes jsonb NOT NULL,
    created timestamp without time zone NOT NULL,
    updated timestamp without time zone NOT NULL
);


ALTER TABLE public.buckets OWNER TO postgres;

--
-- Name: COLUMN buckets.subject; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.buckets.subject IS 'The subject that together with the purpose identify this bucket';


--
-- Name: COLUMN buckets.purpose; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.buckets.purpose IS 'The purpose of this bucket, eg. "login_attempt_counter"';


--
-- Name: COLUMN buckets.attributes; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.buckets.attributes IS 'All attributes stored for this subject/purpose';


--
-- Name: COLUMN buckets.created; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.buckets.created IS 'When this bucket was created';


--
-- Name: COLUMN buckets.updated; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.buckets.updated IS 'When this bucket was last updated';


--
-- Name: delegations; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.delegations (
    id character varying(40) NOT NULL,
    owner character varying(128) NOT NULL,
    created bigint NOT NULL,
    expires bigint NOT NULL,
    scope character varying(1000),
    scope_claims text,
    client_id character varying(128) NOT NULL,
    redirect_uri character varying(512),
    status character varying(16) NOT NULL,
    claims text,
    authentication_attributes text,
    authorization_code_hash character varying(89)
);


ALTER TABLE public.delegations OWNER TO postgres;

--
-- Name: COLUMN delegations.id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.delegations.id IS 'Unique identifier';


--
-- Name: COLUMN delegations.owner; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.delegations.owner IS 'Moment when delegations record is created, as measured in number of seconds since epoch';


--
-- Name: COLUMN delegations.expires; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.delegations.expires IS 'Moment when delegation expires, as measured in number of seconds since epoch';


--
-- Name: COLUMN delegations.scope; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.delegations.scope IS 'Space delimited list of scope values';


--
-- Name: COLUMN delegations.scope_claims; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.delegations.scope_claims IS 'JSON with the scope-claims configuration at the time of delegation issuance';


--
-- Name: COLUMN delegations.client_id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.delegations.client_id IS 'Reference to a client; non-enforced';


--
-- Name: COLUMN delegations.redirect_uri; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.delegations.redirect_uri IS 'Optional value for the redirect_uri parameter, when provided in a request for delegation';


--
-- Name: COLUMN delegations.status; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.delegations.status IS 'Status of the delegation instance, from {''issued'', ''revoked''}';


--
-- Name: COLUMN delegations.claims; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.delegations.claims IS 'Optional JSON that contains a list of claims that are part of the delegation';


--
-- Name: COLUMN delegations.authentication_attributes; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.delegations.authentication_attributes IS 'The JSON-serialized AuthenticationAttributes established for this delegation';


--
-- Name: COLUMN delegations.authorization_code_hash; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.delegations.authorization_code_hash IS 'A hash of the authorization code that was provided when this delegation was issued.';


--
-- Name: devices; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.devices (
    id character varying(64) NOT NULL,
    device_id character varying(64),
    account_id character varying(256),
    external_id character varying(32),
    alias character varying(30),
    form_factor character varying(10),
    device_type character varying(50),
    owner character varying(256),
    attributes jsonb,
    expires bigint,
    created bigint NOT NULL,
    updated bigint NOT NULL
);


ALTER TABLE public.devices OWNER TO postgres;

--
-- Name: COLUMN devices.id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.devices.id IS 'Unique ID of the device';


--
-- Name: COLUMN devices.device_id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.devices.device_id IS 'The device ID that identifies the physical device';


--
-- Name: COLUMN devices.account_id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.devices.account_id IS 'The user account ID that is associated with the device';


--
-- Name: COLUMN devices.external_id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.devices.external_id IS 'The phone or other identifying number of the device (if it has one)';


--
-- Name: COLUMN devices.alias; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.devices.alias IS 'The user-recognizable name or mnemonic identifier of the device (e.g., my work iPhone)';


--
-- Name: COLUMN devices.form_factor; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.devices.form_factor IS 'The type or form of device (e.g., laptop, phone, tablet, etc.)';


--
-- Name: COLUMN devices.device_type; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.devices.device_type IS 'The device type (i.e., make, manufacturer, provider, class)';


--
-- Name: COLUMN devices.owner; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.devices.owner IS 'The owner of the device. This is the user who has administrative rights on the device';


--
-- Name: COLUMN devices.attributes; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.devices.attributes IS 'Key/value map of custom attributes associated with the device.';


--
-- Name: COLUMN devices.expires; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.devices.expires IS 'Time since epoch of device expiration, in seconds';


--
-- Name: COLUMN devices.created; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.devices.created IS 'Time since epoch of device creation, in seconds';


--
-- Name: COLUMN devices.updated; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.devices.updated IS 'Time since epoch of latest device update, in seconds';


--
-- Name: dynamically_registered_clients; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.dynamically_registered_clients (
    client_id character varying(64) NOT NULL,
    client_secret character varying(128),
    instance_of_client character varying(64),
    created timestamp without time zone NOT NULL,
    updated timestamp without time zone NOT NULL,
    initial_client character varying(64),
    authenticated_user character varying(64),
    attributes jsonb DEFAULT '{}'::jsonb NOT NULL,
    status character varying(12) DEFAULT 'active'::character varying NOT NULL,
    scope text,
    redirect_uris text,
    grant_types character varying(128)
);


ALTER TABLE public.dynamically_registered_clients OWNER TO postgres;

--
-- Name: COLUMN dynamically_registered_clients.client_id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.dynamically_registered_clients.client_id IS 'The client ID of this client instance';


--
-- Name: COLUMN dynamically_registered_clients.client_secret; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.dynamically_registered_clients.client_secret IS 'The hash of this client''s secret';


--
-- Name: COLUMN dynamically_registered_clients.instance_of_client; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.dynamically_registered_clients.instance_of_client IS 'The client ID on which this instance is based, or NULL if this is a non-templatized client';


--
-- Name: COLUMN dynamically_registered_clients.created; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.dynamically_registered_clients.created IS 'When this client was originally created (in UTC time)';


--
-- Name: COLUMN dynamically_registered_clients.updated; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.dynamically_registered_clients.updated IS 'When this client was last updated (in UTC time)';


--
-- Name: COLUMN dynamically_registered_clients.initial_client; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.dynamically_registered_clients.initial_client IS 'In case the user authenticated, this value contains a client_id value of the initial token. If the initial token was issued through a client credentials-flow, the initial_client value is set to the client that authenticated. Registration without initial token (i.e. with no authentication) will result in a null value for initial_client';


--
-- Name: COLUMN dynamically_registered_clients.authenticated_user; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.dynamically_registered_clients.authenticated_user IS 'In case a user authenticated (through a client), this value contains the sub value of the initial token';


--
-- Name: COLUMN dynamically_registered_clients.attributes; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.dynamically_registered_clients.attributes IS 'Arbitrary attributes tied to this client';


--
-- Name: COLUMN dynamically_registered_clients.status; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.dynamically_registered_clients.status IS 'The current status of the client, allowed values are "active", "inactive" and "revoked"';


--
-- Name: COLUMN dynamically_registered_clients.scope; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.dynamically_registered_clients.scope IS 'Space separated list of scopes defined for this client (non-templatized clients only)';


--
-- Name: COLUMN dynamically_registered_clients.redirect_uris; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.dynamically_registered_clients.redirect_uris IS 'Space separated list of redirect URI''s defined for this client (non-templatized clients only)';


--
-- Name: COLUMN dynamically_registered_clients.grant_types; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.dynamically_registered_clients.grant_types IS 'Space separated list of grant types defined for this client (non-templatized clients only)';


--
-- Name: linked_accounts; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.linked_accounts (
    account_id character varying(64),
    linked_account_id character varying(64) NOT NULL,
    linked_account_domain_name character varying(64) NOT NULL,
    linking_account_manager character varying(128),
    created timestamp without time zone NOT NULL
);


ALTER TABLE public.linked_accounts OWNER TO postgres;

--
-- Name: COLUMN linked_accounts.account_id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.linked_accounts.account_id IS 'Account ID, typically a global one, of the account being linked from (the linker)';


--
-- Name: COLUMN linked_accounts.linked_account_id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.linked_accounts.linked_account_id IS 'Account ID, typically a local or legacy one, of the account being linked (the linkee)';


--
-- Name: COLUMN linked_accounts.linked_account_domain_name; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.linked_accounts.linked_account_domain_name IS 'The domain (i.e., organizational group or realm) of the account being linked';


--
-- Name: nonces; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.nonces (
    token character varying(64) NOT NULL,
    reference_data text NOT NULL,
    created bigint NOT NULL,
    ttl bigint NOT NULL,
    consumed bigint,
    status character varying(16) DEFAULT 'issued'::character varying NOT NULL
);


ALTER TABLE public.nonces OWNER TO postgres;

--
-- Name: COLUMN nonces.token; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.nonces.token IS 'Value issued as random nonce';


--
-- Name: COLUMN nonces.reference_data; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.nonces.reference_data IS 'Value that is referenced by the nonce value';


--
-- Name: COLUMN nonces.created; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.nonces.created IS 'Moment when nonce record is created, as measured in number of seconds since epoch';


--
-- Name: COLUMN nonces.ttl; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.nonces.ttl IS 'Time To Live, period in seconds since created after which the nonce expires';


--
-- Name: COLUMN nonces.consumed; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.nonces.consumed IS 'Moment when nonce was consumed, as measured in number of seconds since epoch';


--
-- Name: COLUMN nonces.status; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.nonces.status IS 'Status of the nonce from {''issued'', ''revoked'', ''used''}';


--
-- Name: sessions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.sessions (
    id character varying(64) NOT NULL,
    session_data text NOT NULL,
    expires bigint NOT NULL
);


ALTER TABLE public.sessions OWNER TO postgres;

--
-- Name: COLUMN sessions.id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.sessions.id IS 'id given to the session';


--
-- Name: COLUMN sessions.session_data; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.sessions.session_data IS 'Value that is referenced by the session id';


--
-- Name: COLUMN sessions.expires; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.sessions.expires IS 'Moment when session record expires, as measured in number of seconds since epoch';


--
-- Name: tokens; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.tokens (
    token_hash character varying(89) NOT NULL,
    id character varying(64),
    delegations_id character varying(40) NOT NULL,
    purpose character varying(32) NOT NULL,
    usage character varying(8) NOT NULL,
    format character varying(32) NOT NULL,
    created bigint NOT NULL,
    expires bigint NOT NULL,
    scope character varying(1000),
    scope_claims text,
    status character varying(16) NOT NULL,
    issuer character varying(200) NOT NULL,
    subject character varying(64) NOT NULL,
    audience character varying(512),
    not_before bigint,
    claims text,
    meta_data text
);


ALTER TABLE public.tokens OWNER TO postgres;

--
-- Name: COLUMN tokens.token_hash; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.token_hash IS 'Base64 encoded sha-512 hash of the token value.';


--
-- Name: COLUMN tokens.id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.id IS 'Identifier of the token, when it exists; this can be the value from the ''jti''-claim of a JWT, etc. Opaque tokens do not have an id.';


--
-- Name: COLUMN tokens.delegations_id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.delegations_id IS 'Reference to the delegation instance that underlies the token';


--
-- Name: COLUMN tokens.purpose; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.purpose IS 'Purpose of the token, i.e. ''nonce'', ''accesstoken'', ''refreshtoken'', ''custom'', etc.';


--
-- Name: COLUMN tokens.usage; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.usage IS 'Indication whether the token is a bearer or proof token, from {"bearer", "proof"}';


--
-- Name: COLUMN tokens.format; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.format IS 'The format of the token, i.e. ''opaque'', ''jwt'', etc.';


--
-- Name: COLUMN tokens.created; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.created IS 'Moment when token record is created, as measured in number of seconds since epoch';


--
-- Name: COLUMN tokens.expires; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.expires IS 'Moment when token expires, as measured in number of seconds since epoch';


--
-- Name: COLUMN tokens.scope; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.scope IS 'Space delimited list of scope values';


--
-- Name: COLUMN tokens.scope_claims; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.scope_claims IS 'Space delimited list of scope-claims values';


--
-- Name: COLUMN tokens.status; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.status IS 'Status of the token from {''issued'', ''used'', ''revoked''}';


--
-- Name: COLUMN tokens.issuer; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.issuer IS 'Optional name of the issuer of the token (jwt.iss)';


--
-- Name: COLUMN tokens.subject; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.subject IS 'Optional subject of the token (jwt.sub)';


--
-- Name: COLUMN tokens.audience; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.audience IS 'Space separated list of audiences for the token (jwt.aud)';


--
-- Name: COLUMN tokens.not_before; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.not_before IS 'Moment before which the token is not valid, as measured in number of seconds since epoch (jwt.nbf)';


--
-- Name: COLUMN tokens.claims; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.tokens.claims IS 'Optional JSON-blob that contains a list of claims that are part of the token';


--
-- Data for Name: accounts; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.accounts (account_id, username, password, email, phone, attributes, active, created, updated) FROM stdin;
31e074f4-7c73-11ed-bac3-0242ac1a0002	johndoe	$5$rounds=20000$pgQ4O5vncx8qjv2C$yzYlyDwcrJc/VwiPPX.f3CUsLoKy8GEut6gTRZOawH0	john.doe@company.com	\N	{"name": {"givenName": "John", "familyName": "Doe"}, "title": "", "emails": [{"type": "", "value": "john.doe@company.com", "primary": true}], "groups": [{"type": "", "value": "devops", "primary": true}], "locale": "", "nickName": "", "addresses": [], "displayName": "John Doe", "entitlements": [], "phoneNumbers": []}	1	1671106971	1671106971
\.


--
-- Data for Name: audit; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.audit (id, instant, event_instant, server, message, event_type, subject, client, resource, authenticated_subject, authenticated_client, acr, endpoint, session) FROM stdin;
\.


--
-- Data for Name: buckets; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.buckets (subject, purpose, attributes, created, updated) FROM stdin;
\.


--
-- Data for Name: delegations; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.delegations (id, owner, created, expires, scope, scope_claims, client_id, redirect_uri, status, claims, authentication_attributes, authorization_code_hash) FROM stdin;
ff3cd915-163d-4426-834a-453c179ec039	admin	1671101995	1671102295	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":["admin"]},"delegation-version":"4.1"}	{"subject":{"username":"admin","subject":"admin"},"context":{"iat":1671101994752,"auth_time":1671101994,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"qH1JqO9Cnj5myK6L"}}}	9aXX5V74GfNOGOf82XaXforImRklkfSnSvLEo/hj/sWqYghj+vTXBk+z4gu/QpZjt1+e7TCqpsxrg6YFM3pdAg==
a3f01399-17e3-4ff4-8fc5-718c725fa4f6	admin	1671102309	1671102609	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":["admin"]},"delegation-version":"4.1"}	{"subject":{"username":"admin","subject":"admin"},"context":{"iat":1671102309702,"auth_time":1671102309,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"JpprER3Ce8zX9Fmj"}}}	wq3GXdwiRa16i7XBN72P4rOSedSyHueBUYqp+2iVpnqx++S/7ueC48414nZp30bie0OOylvMrL4WfBgSV5WBKw==
672b47d8-7688-4c65-aca8-e9b092327cd8	admin	1671102679	1671102979	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":["admin"]},"delegation-version":"4.1"}	{"subject":{"username":"admin","subject":"admin"},"context":{"iat":1671102309702,"auth_time":1671102309,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"JpprER3Ce8zX9Fmj"}}}	STfZuBWWXrHLmxwUrGN+w6rEQWSVd9NkB4ooSlC7sr4MzmJ36AbMctHX7qwo+jqZ/VE0dXdAyZlZvRuSaUN6vA==
a1ff7fca-f3f3-4cc3-ab17-a04f6a45859f	admin	1671103025	1671103325	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":["admin"]},"delegation-version":"4.1"}	{"subject":{"username":"admin","subject":"admin"},"context":{"iat":1671102309702,"auth_time":1671102309,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"JpprER3Ce8zX9Fmj"}}}	HKP6Ad+5rnGjolryZxXOwqGwFFsxClY0rznCqpochKjitlSz0FU0+pRsYzXvMOujiKoes5kKlpflQzS0GA1r5w==
bb691089-1193-4263-860f-905ccd987051	admin	1671103311	1671103611	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":["admin"]},"delegation-version":"4.1"}	{"subject":{"username":"admin","subject":"admin"},"context":{"iat":1671102309702,"auth_time":1671102309,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"JpprER3Ce8zX9Fmj"}}}	xTdjbU64rVk9C1nKI4jBgraAbWY3W1xBIAa2bEMjeMitPL92WEA/sJ5/LEi2PQPvNaObzITAvI+zOx8Kn4dD5g==
553b07cf-ef1c-4f63-9e27-56c546b62b24	scim-client	1671104994	1671105294	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671104994}}	\N
e64aea35-c3ba-4f02-ac54-b8beb269239e	admin	1671103860	1671104160	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":["admin"]},"delegation-version":"4.1"}	{"subject":{"username":"admin","subject":"admin"},"context":{"iat":1671102309702,"auth_time":1671102309,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"JpprER3Ce8zX9Fmj"}}}	ir76FDdxNRdvxLpBxhxthjFYyhEzDlLhEqA72tTbdBPq+nhXPx1ax1Weuh5ZwzoJ6o5dzSVJoZ2Ih5JXsQRysA==
91cc6b7a-7e71-44ef-8af3-7a4db5fa8cac	admin	1671104115	1671104415	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":["admin"]},"delegation-version":"4.1"}	{"subject":{"username":"admin","subject":"admin"},"context":{"iat":1671102309702,"auth_time":1671102309,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"JpprER3Ce8zX9Fmj"}}}	W/B749fmYEKCTbM3woY1r/JMs7StQvFvwrCre22GzSkIn5o6XHvdIsuXZoJLmgfYnL275Log3nrfC6n7eObZdg==
c38b2658-295b-4bc6-8ae2-45ee31cca11f	scim-client	1671104507	1671104807	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671104507}}	\N
6f5ee3df-aad6-4493-a9c0-cc9e822087cb	scim-client	1671104591	1671104891	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671104591}}	\N
f27cd88c-712f-4655-a7fe-ec4d8be70eb6	scim-client	1671104609	1671104909	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671104609}}	\N
0e4592b5-709e-4ff9-852f-de726bad4f3b	scim-client	1671104639	1671104939	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671104639}}	\N
89a4c979-bc11-4eb4-8834-e5378d12bf3f	scim-client	1671104714	1671105014	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671104714}}	\N
ba633d05-f5b0-4fbf-a06f-e16b9e20ee8f	scim-client	1671104779	1671105079	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671104779}}	\N
a39147bd-3d95-4a7a-a2d8-b18772fe1f75	scim-client	1671105014	1671105314	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671105014}}	\N
9990283c-73cf-40a2-b04e-68c061c505e6	scim-client	1671105021	1671105321	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671105021}}	\N
f54a818a-ab50-4c0a-98bd-b14dc0baa044	scim-client	1671105090	1671105390	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671105090}}	\N
89b70705-cc69-4827-9886-5714c7862283	scim-client	1671105153	1671105453	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671105153}}	\N
5f3823e5-6919-460c-a882-93d5b9abe00c	scim-client	1671105266	1671105566	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671105266}}	\N
3c11bc7a-ba28-4f3c-88f7-08eab8c5adab	scim-client	1671105282	1671105582	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671105282}}	\N
8866d63f-c71f-4ed0-a91f-51a9d41ae4cf	scim-client	1671105694	1671105994	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671105694}}	\N
b197eee7-7f05-460a-a47f-036b4bcc068a	scim-client	1671105850	1671106150	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671105850}}	\N
9f1d4d9c-863a-4aa8-b0ae-0e994fdb3b4b	scim-client	1671105897	1671106197	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671105897}}	\N
cbf17090-d9fd-4e7f-998f-7f321adeb06c	scim-client	1671105925	1671106225	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671105925}}	\N
5cdea1f7-53a0-46da-9d9b-b6ee44d14439	scim-client	1671105975	1671106275	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671105975}}	\N
268c5fb4-ef37-4f93-9ed6-5eeb61e41799	scim-client	1671106015	1671106315	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671106015}}	\N
8914fbad-9137-4e39-90a7-c1cf7471f66d	scim-client	1671106083	1671106383	accounts	[{"scope":"accounts","claim":"groups","required":false}]	scim-client	\N	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":"admin"},"delegation-version":"4.1"}	{"subject":{"subject":"scim-client"},"context":{"_requestingClientAuthenticationMethod":"secret","auth_time":1671106083}}	\N
d9a65ab6-cbbe-4c4a-84ca-e462711b2919	admin	1671106319	1671106619	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":["admin"]},"delegation-version":"4.1"}	{"subject":{"username":"admin","subject":"admin"},"context":{"iat":1671106319142,"auth_time":1671106319,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"4qQl983pW524D0AD"}}}	74TXFoEplA1zjew2hJBy64ym3dzPmw8WImPv5NoJ4+DNTraiIfoLrSlHqeX10Kj1KYUeanagrPwL6g+4D7aIzw==
a44d96c6-5f76-49ad-a54c-c663455b75b8	admin	1671106827	1671107127	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":["admin"]},"delegation-version":"4.1"}	{"subject":{"username":"admin","subject":"admin"},"context":{"iat":1671106319142,"auth_time":1671106319,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"4qQl983pW524D0AD"}}}	fFBYTNcIyuZQyF9/PDd/6LuAcOQX5ZhSPXZwtuXn6WzrrTgZFQz/RAcv9ABsJvhECNJMYYbm+z3oZudj1aqeUA==
b1b33041-0024-4acc-9bb3-f08b999746d8	admin	1671106928	1671107228	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":["admin"]},"delegation-version":"4.1"}	{"subject":{"username":"admin","subject":"admin"},"context":{"iat":1671106319142,"auth_time":1671106319,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"4qQl983pW524D0AD"}}}	fcLqM2spaL38QAHVdy55gd8+8vz58JvqggHvya01LBZsAZxD3wAooxrn/sfmItMgcuX4xKrMpETFs/1ehf/duA==
e8a5ebf5-183e-4fec-b4d8-c528a37faa30	johndoe	1671107013	1671107313	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":[]},"delegation-version":"4.1"}	{"subject":{"accountId":"31e074f4-7c73-11ed-bac3-0242ac1a0002","userName":"johndoe","subject":"johndoe"},"context":{"auth_time":1671107012,"acr":"urn:se:curity:authentication:html-form:htmlform","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"VkHLE3u9k7roPzZy"}}}	NvLNsXPrmaNlE7MDMP1/hHuVoXxWU9DlODebqGVS87kZwnG6MCNCnNrW0DucIWqmeCMoZhOirRWb4rV/PR47XQ==
ceb53c87-d0db-4835-a3d2-b5acb3ca3666	johndoe	1671107059	1671107359	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":[]},"delegation-version":"4.1"}	{"subject":{"accountId":"31e074f4-7c73-11ed-bac3-0242ac1a0002","userName":"johndoe","subject":"johndoe"},"context":{"auth_time":1671107012,"acr":"urn:se:curity:authentication:html-form:htmlform","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"VkHLE3u9k7roPzZy"}}}	JsnxwSdg9o2bw4M/nKNtIsg3s4JflsCkZOPrAGQ8l5iDBMSL39SL4bJkLF5OmyByuMx7tJejgz6bv9F6SnyUQg==
ccc4f07a-ba90-4520-9d1c-0b1778ccedb2	johndoe	1671109097	1671109397	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":[]},"delegation-version":"4.1"}	{"subject":{"accountId":"31e074f4-7c73-11ed-bac3-0242ac1a0002","userName":"johndoe","subject":"johndoe"},"context":{"auth_time":1671109097,"acr":"urn:se:curity:authentication:html-form:htmlform","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"LqrkC0VYM1Np6xrj"}}}	OX3oztNv6Y3ZuvOPGFMmfR5mgPdeMHB/+Uxz66fUbNGUBaKCj3lX2O54VkbUcLUFKwz2LyEacjUQ7BKIqT2/Ew==
a12eeaea-be08-421e-b225-efcaf176d814	johndoe	1671109157	1671109457	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":[]},"delegation-version":"4.1"}	{"subject":{"accountId":"31e074f4-7c73-11ed-bac3-0242ac1a0002","userName":"johndoe","subject":"johndoe"},"context":{"auth_time":1671109157,"acr":"urn:se:curity:authentication:html-form:htmlform","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"sxcRO3X5rrPvRmNF"}}}	5z/d7saaeuZF19fJqgYVlXWwe+ppYrTzuE8+ERR866lbQmUTFylrcjQ/mFR/DssrpCPxmL4HdOZUT1lChxMJhg==
4dfa02eb-d7ba-4192-a94f-f393a5bef0c7	johndoe	1671109173	1671109473	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":[]},"delegation-version":"4.1"}	{"subject":{"accountId":"31e074f4-7c73-11ed-bac3-0242ac1a0002","userName":"johndoe","subject":"johndoe"},"context":{"auth_time":1671109157,"acr":"urn:se:curity:authentication:html-form:htmlform","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"sxcRO3X5rrPvRmNF"}}}	Z30a/+UN0AXk5+BHTusRsdnYMtL5M55aaUHuJjKscyJwlrhXy3QM0LYASvcQazYhhVXIGbQr4ViSehhyZjmYFw==
43c02b5b-dd1e-4d81-a7cb-5a4febd4398b	johndoe	1671109194	1671109494	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":[]},"delegation-version":"4.1"}	{"subject":{"accountId":"31e074f4-7c73-11ed-bac3-0242ac1a0002","userName":"johndoe","subject":"johndoe"},"context":{"auth_time":1671109194,"acr":"urn:se:curity:authentication:html-form:htmlform","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"tl0nNQT1X1brp5Oq"}}}	w5M+Xfv7ZAXvsBpO+LY47JyzdNCccwyi5BsJP2I4F2y+oYtJpRWHpOD+vG9In6507eVkGJijrXQYEXAERsBBqg==
a43f4b24-4d65-4ac8-9397-69157aac1617	johndoe	1671109227	1671109527	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":[]},"delegation-version":"4.1"}	{"subject":{"accountId":"31e074f4-7c73-11ed-bac3-0242ac1a0002","userName":"johndoe","subject":"johndoe"},"context":{"auth_time":1671109226,"acr":"urn:se:curity:authentication:html-form:htmlform","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"X6CfMfCVNNtfNY00"}}}	S/oF09ZvvGoAzZHxdq1RSBBtjcvk8OusEyjD7XxWLBrG0eKblA7PjVC4W0iCqRNXXcVSiAKpktarVF3gx3eJHQ==
ac5585b3-5e79-490c-adcf-0df17ac56248	johndoe	1671109352	1671109652	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"urn:se:curity:claims:admin:groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"urn:se:curity:claims:admin:groups":[]},"delegation-version":"4.1"}	{"subject":{"accountId":"31e074f4-7c73-11ed-bac3-0242ac1a0002","userName":"johndoe","subject":"johndoe"},"context":{"auth_time":1671109352,"acr":"urn:se:curity:authentication:html-form:htmlform","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"zCTZUP1OYrm4KR5g"}}}	5S3lHnyOjJAleSpFf/TPO6i4B4qa6pLTw+gguLhXwnXFY0irxJO1X/3ehDWfjXyyW+XkcxguF0tnr+2LVM6cvA==
\.


--
-- Data for Name: devices; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.devices (id, device_id, account_id, external_id, alias, form_factor, device_type, owner, attributes, expires, created, updated) FROM stdin;
\.


--
-- Data for Name: dynamically_registered_clients; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.dynamically_registered_clients (client_id, client_secret, instance_of_client, created, updated, initial_client, authenticated_user, attributes, status, scope, redirect_uris, grant_types) FROM stdin;
\.


--
-- Data for Name: linked_accounts; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.linked_accounts (account_id, linked_account_id, linked_account_domain_name, linking_account_manager, created) FROM stdin;
\.


--
-- Data for Name: nonces; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.nonces (token, reference_data, created, ttl, consumed, status) FROM stdin;
Ihak3hXS5FjgfVEgHySyI5jvXHACTWCn	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDIyOTQsImNyZWF0ZWQiOjE2NzExMDE5OTQsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTAxOTk0NzUyLCJhdXRoX3RpbWUiOjE2NzExMDE5OTQsImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoicUgxSnFPOUNuajVteUs2TCJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjFjOTQwY2ZjLWYzZWItNGMwZi04NmRlLWVjNDg5M2VjMDk4YiIsInN1YmplY3QiOnsidXNlcm5hbWUiOiJhZG1pbiIsInN1YmplY3QiOiJhZG1pbiJ9fX0=	1671101994	300	1671101994	used
3GXYZ5juL4MaKWVTKQYjUAkaeGqNb0A3	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDIwMjQsImNyZWF0ZWQiOjE2NzExMDE5OTQsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJhZG1pbiIsInJlZGlyZWN0VXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OS9hZG1pbi9kYXNoYm9hcmQvYXNzaXN0ZWQuaHRtbCIsImF1ZGllbmNlIjpbInVybjpzZTpjdXJpdHk6YXVkaWVuY2VzOmFkbWluOmFwaSIsImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Il0sImNsaWVudElkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJyZWRpcmVjdFVyaVByb3ZpZGVkIjp0cnVlLCJhdXRoZW50aWNhdGlvbkF0dHJpYnV0ZXMiOnsic3ViamVjdCI6eyJ1c2VybmFtZSI6ImFkbWluIiwic3ViamVjdCI6ImFkbWluIn0sImNvbnRleHQiOnsiaWF0IjoxNjcxMTAxOTk0NzUyLCJhdXRoX3RpbWUiOjE2NzExMDE5OTQsImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoicUgxSnFPOUNuajVteUs2TCJ9fX0sImNvZGVDaGFsbGVuZ2VNZXRob2QiOiJTMjU2Iiwibm9uY2UiOiJWSGZQT0N5RzgzU2ZxZWo3TjZGQUdUQVp4ZWdTNks0UU5mOWR6TGprQW5LcURrT2hmYVNpNnFRZTU4UTI1WWh2Iiwic2lkIjoicUgxSnFPOUNuajVteUs2TCIsInNjb3BlIjoib3BlbmlkIHVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSIsImNsYWltcyI6eyJ1bm1hcHBlZENsYWltcyI6eyJ1cm46c2U6Y3VyaXR5OmNsYWltczphZG1pbjpncm91cHMiOnsic2NvcGVzIjpbInVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSJdfSwiaXNzIjp7InJlcXVpcmVkIjp0cnVlfSwic3ViIjp7InJlcXVpcmVkIjp0cnVlfSwiYXVkIjp7InJlcXVpcmVkIjp0cnVlfSwiZXhwIjp7InJlcXVpcmVkIjp0cnVlfSwiaWF0Ijp7InJlcXVpcmVkIjp0cnVlfSwiYXV0aF90aW1lIjp7InJlcXVpcmVkIjp0cnVlfSwibm9uY2UiOnsicmVxdWlyZWQiOnRydWV9LCJhY3IiOnsicmVxdWlyZWQiOnRydWV9LCJhbXIiOnsicmVxdWlyZWQiOnRydWV9LCJhenAiOnsicmVxdWlyZWQiOnRydWV9LCJuYmYiOnsicmVxdWlyZWQiOnRydWV9LCJjbGllbnRfaWQiOnsicmVxdWlyZWQiOnRydWV9LCJkZWxlZ2F0aW9uX2lkIjp7InJlcXVpcmVkIjp0cnVlfSwicHVycG9zZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNjb3BlIjp7InJlcXVpcmVkIjp0cnVlfSwianRpIjp7InJlcXVpcmVkIjp0cnVlfSwic2lkIjp7InJlcXVpcmVkIjp0cnVlfX19LCJjb2RlQ2hhbGxlbmdlIjoiSjh2WE13dDhSS3BHSVlGSDdXM3Q2TmpiaVZQZXZIa2wwNlF4bC1Xb1AxNCIsInN0YXRlIjoiUjNPYTE4TTNqQUxHUTFBa0J5U3k4ZENRM3pNcnRXSzdaR0Y3YjhKMnlMR3BsR3N5TTNLWTBZTDhPTFVwVFlJVyJ9fQ==	1671101994	30	1671101995	used
3tISiv4x9kkaiyHi2c4Gjlc4vsqEd6Nu	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDI2MDksImNyZWF0ZWQiOjE2NzExMDIzMDksInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTAyMzA5NzAyLCJhdXRoX3RpbWUiOjE2NzExMDIzMDksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjFjOTQwY2ZjLWYzZWItNGMwZi04NmRlLWVjNDg5M2VjMDk4YiIsInN1YmplY3QiOnsidXNlcm5hbWUiOiJhZG1pbiIsInN1YmplY3QiOiJhZG1pbiJ9fX0=	1671102309	300	1671102309	used
UaMmisOEdCpUsiJMtZP0IW9ZKznd1qqt	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDIzMzksImNyZWF0ZWQiOjE2NzExMDIzMDksInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJhZG1pbiIsInJlZGlyZWN0VXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OS9hZG1pbi9kYXNoYm9hcmQvYXNzaXN0ZWQuaHRtbCIsImF1ZGllbmNlIjpbInVybjpzZTpjdXJpdHk6YXVkaWVuY2VzOmFkbWluOmFwaSIsImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Il0sImNsaWVudElkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJyZWRpcmVjdFVyaVByb3ZpZGVkIjp0cnVlLCJhdXRoZW50aWNhdGlvbkF0dHJpYnV0ZXMiOnsic3ViamVjdCI6eyJ1c2VybmFtZSI6ImFkbWluIiwic3ViamVjdCI6ImFkbWluIn0sImNvbnRleHQiOnsiaWF0IjoxNjcxMTAyMzA5NzAyLCJhdXRoX3RpbWUiOjE2NzExMDIzMDksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiJ9fX0sImNvZGVDaGFsbGVuZ2VNZXRob2QiOiJTMjU2Iiwibm9uY2UiOiJwUk43aXplWTlzWE1yV0RWWHVEYmpvaTRaQTllcDRvRm43cHBNTjFDWFR6Rk50V1YxS0dkM0JFam5jdjU5NW9hIiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiIsInNjb3BlIjoib3BlbmlkIHVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSIsImNsYWltcyI6eyJ1bm1hcHBlZENsYWltcyI6eyJ1cm46c2U6Y3VyaXR5OmNsYWltczphZG1pbjpncm91cHMiOnsic2NvcGVzIjpbInVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSJdfSwiaXNzIjp7InJlcXVpcmVkIjp0cnVlfSwic3ViIjp7InJlcXVpcmVkIjp0cnVlfSwiYXVkIjp7InJlcXVpcmVkIjp0cnVlfSwiZXhwIjp7InJlcXVpcmVkIjp0cnVlfSwiaWF0Ijp7InJlcXVpcmVkIjp0cnVlfSwiYXV0aF90aW1lIjp7InJlcXVpcmVkIjp0cnVlfSwibm9uY2UiOnsicmVxdWlyZWQiOnRydWV9LCJhY3IiOnsicmVxdWlyZWQiOnRydWV9LCJhbXIiOnsicmVxdWlyZWQiOnRydWV9LCJhenAiOnsicmVxdWlyZWQiOnRydWV9LCJuYmYiOnsicmVxdWlyZWQiOnRydWV9LCJjbGllbnRfaWQiOnsicmVxdWlyZWQiOnRydWV9LCJkZWxlZ2F0aW9uX2lkIjp7InJlcXVpcmVkIjp0cnVlfSwicHVycG9zZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNjb3BlIjp7InJlcXVpcmVkIjp0cnVlfSwianRpIjp7InJlcXVpcmVkIjp0cnVlfSwic2lkIjp7InJlcXVpcmVkIjp0cnVlfX19LCJjb2RlQ2hhbGxlbmdlIjoieTFCT05kV1hrakhnTVdXWU5IaWowZkcwWk5PcVBiMDIxUmFvM0U4T19kSSIsInN0YXRlIjoibFJjN2lHVWJEOFdtTWNieGJoTEhGQURQNTA3aUJTU3o1Z1VwSFRhZXJHTDltbXhnN1YxdjNFR1pFSDVzdkNvaCJ9fQ==	1671102309	30	1671102309	used
0ubb6F9Cc8l1S8Yur262HE2uyUgTr7cr	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDI5NzksImNyZWF0ZWQiOjE2NzExMDI2NzksInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTAyMzA5NzAyLCJhdXRoX3RpbWUiOjE2NzExMDIzMDksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjFjOTQwY2ZjLWYzZWItNGMwZi04NmRlLWVjNDg5M2VjMDk4YiIsInN1YmplY3QiOnsidXNlcm5hbWUiOiJhZG1pbiIsInN1YmplY3QiOiJhZG1pbiJ9fX0=	1671102679	300	1671102679	used
fv7UlxSfIuHAVqclo1ymsIflr52eN7Yw	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDI3MDksImNyZWF0ZWQiOjE2NzExMDI2NzksInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJhZG1pbiIsInJlZGlyZWN0VXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OS9hZG1pbi9kYXNoYm9hcmQvYXNzaXN0ZWQuaHRtbCIsImF1ZGllbmNlIjpbInVybjpzZTpjdXJpdHk6YXVkaWVuY2VzOmFkbWluOmFwaSIsImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Il0sImNsaWVudElkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJyZWRpcmVjdFVyaVByb3ZpZGVkIjp0cnVlLCJhdXRoZW50aWNhdGlvbkF0dHJpYnV0ZXMiOnsic3ViamVjdCI6eyJ1c2VybmFtZSI6ImFkbWluIiwic3ViamVjdCI6ImFkbWluIn0sImNvbnRleHQiOnsiaWF0IjoxNjcxMTAyMzA5NzAyLCJhdXRoX3RpbWUiOjE2NzExMDIzMDksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiJ9fX0sImNvZGVDaGFsbGVuZ2VNZXRob2QiOiJTMjU2Iiwibm9uY2UiOiI4WnpXMXRxU2xHQXBCOXZGNWNLNG45b0pDazNYWDNkalRrMmEzbmhBWThCNFJhVUd1bEFHTEdGTDUwNWN4d05jIiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiIsInNjb3BlIjoib3BlbmlkIHVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSIsImNsYWltcyI6eyJ1bm1hcHBlZENsYWltcyI6eyJ1cm46c2U6Y3VyaXR5OmNsYWltczphZG1pbjpncm91cHMiOnsic2NvcGVzIjpbInVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSJdfSwiaXNzIjp7InJlcXVpcmVkIjp0cnVlfSwic3ViIjp7InJlcXVpcmVkIjp0cnVlfSwiYXVkIjp7InJlcXVpcmVkIjp0cnVlfSwiZXhwIjp7InJlcXVpcmVkIjp0cnVlfSwiaWF0Ijp7InJlcXVpcmVkIjp0cnVlfSwiYXV0aF90aW1lIjp7InJlcXVpcmVkIjp0cnVlfSwibm9uY2UiOnsicmVxdWlyZWQiOnRydWV9LCJhY3IiOnsicmVxdWlyZWQiOnRydWV9LCJhbXIiOnsicmVxdWlyZWQiOnRydWV9LCJhenAiOnsicmVxdWlyZWQiOnRydWV9LCJuYmYiOnsicmVxdWlyZWQiOnRydWV9LCJjbGllbnRfaWQiOnsicmVxdWlyZWQiOnRydWV9LCJkZWxlZ2F0aW9uX2lkIjp7InJlcXVpcmVkIjp0cnVlfSwicHVycG9zZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNjb3BlIjp7InJlcXVpcmVkIjp0cnVlfSwianRpIjp7InJlcXVpcmVkIjp0cnVlfSwic2lkIjp7InJlcXVpcmVkIjp0cnVlfX19LCJjb2RlQ2hhbGxlbmdlIjoieVV1OGNKeVhpbFM1TnlYMGRMclFSMEVtRWNzeEVQWFBIZndBSGktYWdvYyIsInN0YXRlIjoidHpUSUFyWHVaSjlYRjRFZWVZSGpQUUJKQlEzSE11VTlsbzdZb01EQ2ljYzdTZEJjM2o1cjBXTG56dU04QWpUaSJ9fQ==	1671102679	30	1671102679	used
XKbAaMCcYEpRfucDtuJXiaOJuMg17o1n	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDMzMjUsImNyZWF0ZWQiOjE2NzExMDMwMjUsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTAyMzA5NzAyLCJhdXRoX3RpbWUiOjE2NzExMDIzMDksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjFjOTQwY2ZjLWYzZWItNGMwZi04NmRlLWVjNDg5M2VjMDk4YiIsInN1YmplY3QiOnsidXNlcm5hbWUiOiJhZG1pbiIsInN1YmplY3QiOiJhZG1pbiJ9fX0=	1671103025	300	1671103025	used
DmQVyYOx3egj90VBzU6Ksnkdz1HUQwH9	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDMwNTUsImNyZWF0ZWQiOjE2NzExMDMwMjUsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJhZG1pbiIsInJlZGlyZWN0VXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OS9hZG1pbi9kYXNoYm9hcmQvYXNzaXN0ZWQuaHRtbCIsImF1ZGllbmNlIjpbInVybjpzZTpjdXJpdHk6YXVkaWVuY2VzOmFkbWluOmFwaSIsImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Il0sImNsaWVudElkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJyZWRpcmVjdFVyaVByb3ZpZGVkIjp0cnVlLCJhdXRoZW50aWNhdGlvbkF0dHJpYnV0ZXMiOnsic3ViamVjdCI6eyJ1c2VybmFtZSI6ImFkbWluIiwic3ViamVjdCI6ImFkbWluIn0sImNvbnRleHQiOnsiaWF0IjoxNjcxMTAyMzA5NzAyLCJhdXRoX3RpbWUiOjE2NzExMDIzMDksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiJ9fX0sImNvZGVDaGFsbGVuZ2VNZXRob2QiOiJTMjU2Iiwibm9uY2UiOiJ6REhXeXVIbWphS2tDTjkzanZES1Y5MWp1dUdoWlpQWjY0aWJDOUZPdG1UVDA4Z2RXWTVKNGZqVjBzaWlMaVJaIiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiIsInNjb3BlIjoib3BlbmlkIHVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSIsImNsYWltcyI6eyJ1bm1hcHBlZENsYWltcyI6eyJ1cm46c2U6Y3VyaXR5OmNsYWltczphZG1pbjpncm91cHMiOnsic2NvcGVzIjpbInVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSJdfSwiaXNzIjp7InJlcXVpcmVkIjp0cnVlfSwic3ViIjp7InJlcXVpcmVkIjp0cnVlfSwiYXVkIjp7InJlcXVpcmVkIjp0cnVlfSwiZXhwIjp7InJlcXVpcmVkIjp0cnVlfSwiaWF0Ijp7InJlcXVpcmVkIjp0cnVlfSwiYXV0aF90aW1lIjp7InJlcXVpcmVkIjp0cnVlfSwibm9uY2UiOnsicmVxdWlyZWQiOnRydWV9LCJhY3IiOnsicmVxdWlyZWQiOnRydWV9LCJhbXIiOnsicmVxdWlyZWQiOnRydWV9LCJhenAiOnsicmVxdWlyZWQiOnRydWV9LCJuYmYiOnsicmVxdWlyZWQiOnRydWV9LCJjbGllbnRfaWQiOnsicmVxdWlyZWQiOnRydWV9LCJkZWxlZ2F0aW9uX2lkIjp7InJlcXVpcmVkIjp0cnVlfSwicHVycG9zZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNjb3BlIjp7InJlcXVpcmVkIjp0cnVlfSwianRpIjp7InJlcXVpcmVkIjp0cnVlfSwic2lkIjp7InJlcXVpcmVkIjp0cnVlfX19LCJjb2RlQ2hhbGxlbmdlIjoiZlBhR2JDVFFNbm9UdjhPNE9fbFowOExLeHhUbktSQVBBbUtCMDJFQXFKVSIsInN0YXRlIjoiSGp2a0FzSlFkMWdIRW5qSGVFZFBOT0h0cWllWXl1MXdYZnlPV2JXa0pzQkh6WjM0Ykx0YUh4Wmp6eWM5d0JCSSJ9fQ==	1671103025	30	1671103025	used
2A6lYoFFZvjpGahB0IYV1IZs1dbuBA6B	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDM2MTEsImNyZWF0ZWQiOjE2NzExMDMzMTEsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTAyMzA5NzAyLCJhdXRoX3RpbWUiOjE2NzExMDIzMDksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjFjOTQwY2ZjLWYzZWItNGMwZi04NmRlLWVjNDg5M2VjMDk4YiIsInN1YmplY3QiOnsidXNlcm5hbWUiOiJhZG1pbiIsInN1YmplY3QiOiJhZG1pbiJ9fX0=	1671103311	300	1671103311	used
ewbhrAiKDUIS6RupFDOTyy79nh93t7jf	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDMzNDEsImNyZWF0ZWQiOjE2NzExMDMzMTEsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJhZG1pbiIsInJlZGlyZWN0VXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OS9hZG1pbi9kYXNoYm9hcmQvYXNzaXN0ZWQuaHRtbCIsImF1ZGllbmNlIjpbInVybjpzZTpjdXJpdHk6YXVkaWVuY2VzOmFkbWluOmFwaSIsImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Il0sImNsaWVudElkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJyZWRpcmVjdFVyaVByb3ZpZGVkIjp0cnVlLCJhdXRoZW50aWNhdGlvbkF0dHJpYnV0ZXMiOnsic3ViamVjdCI6eyJ1c2VybmFtZSI6ImFkbWluIiwic3ViamVjdCI6ImFkbWluIn0sImNvbnRleHQiOnsiaWF0IjoxNjcxMTAyMzA5NzAyLCJhdXRoX3RpbWUiOjE2NzExMDIzMDksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiJ9fX0sImNvZGVDaGFsbGVuZ2VNZXRob2QiOiJTMjU2Iiwibm9uY2UiOiJIVUdiR1RucW14ejM0eGFzbGU0eXdaTzBnaUFqVVpiSHcxbkdjN0xZREVybFZvVXJMZUdHQnp5RHNFWW9yck9BIiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiIsInNjb3BlIjoib3BlbmlkIHVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSIsImNsYWltcyI6eyJ1bm1hcHBlZENsYWltcyI6eyJ1cm46c2U6Y3VyaXR5OmNsYWltczphZG1pbjpncm91cHMiOnsic2NvcGVzIjpbInVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSJdfSwiaXNzIjp7InJlcXVpcmVkIjp0cnVlfSwic3ViIjp7InJlcXVpcmVkIjp0cnVlfSwiYXVkIjp7InJlcXVpcmVkIjp0cnVlfSwiZXhwIjp7InJlcXVpcmVkIjp0cnVlfSwiaWF0Ijp7InJlcXVpcmVkIjp0cnVlfSwiYXV0aF90aW1lIjp7InJlcXVpcmVkIjp0cnVlfSwibm9uY2UiOnsicmVxdWlyZWQiOnRydWV9LCJhY3IiOnsicmVxdWlyZWQiOnRydWV9LCJhbXIiOnsicmVxdWlyZWQiOnRydWV9LCJhenAiOnsicmVxdWlyZWQiOnRydWV9LCJuYmYiOnsicmVxdWlyZWQiOnRydWV9LCJjbGllbnRfaWQiOnsicmVxdWlyZWQiOnRydWV9LCJkZWxlZ2F0aW9uX2lkIjp7InJlcXVpcmVkIjp0cnVlfSwicHVycG9zZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNjb3BlIjp7InJlcXVpcmVkIjp0cnVlfSwianRpIjp7InJlcXVpcmVkIjp0cnVlfSwic2lkIjp7InJlcXVpcmVkIjp0cnVlfX19LCJjb2RlQ2hhbGxlbmdlIjoiemptYXktbnZIMEY1U1pMSGpxczUyNTJZYmFXQTBiekpUMFZlRHYtVnVkcyIsInN0YXRlIjoiMmRBVlRvaEUxTHZYRmRScUdFa0ZHMTN6VXNZZ3QxS2hRMm1odjdsY0pMSjBzblo4a2VCeHhtT05yQkJUUGZ0MCJ9fQ==	1671103311	30	1671103311	used
dqO1YRr8zuUwnsfHViMAQIa2m1x6mBu9	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDQxNjAsImNyZWF0ZWQiOjE2NzExMDM4NjAsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTAyMzA5NzAyLCJhdXRoX3RpbWUiOjE2NzExMDIzMDksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjFjOTQwY2ZjLWYzZWItNGMwZi04NmRlLWVjNDg5M2VjMDk4YiIsInN1YmplY3QiOnsidXNlcm5hbWUiOiJhZG1pbiIsInN1YmplY3QiOiJhZG1pbiJ9fX0=	1671103860	300	1671103860	used
VtZEra7pYCWWkvGlGXbeWBPEFQRh8PSv	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDM4OTAsImNyZWF0ZWQiOjE2NzExMDM4NjAsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJhZG1pbiIsInJlZGlyZWN0VXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OS9hZG1pbi9kYXNoYm9hcmQvYXNzaXN0ZWQuaHRtbCIsImF1ZGllbmNlIjpbInVybjpzZTpjdXJpdHk6YXVkaWVuY2VzOmFkbWluOmFwaSIsImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Il0sImNsaWVudElkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJyZWRpcmVjdFVyaVByb3ZpZGVkIjp0cnVlLCJhdXRoZW50aWNhdGlvbkF0dHJpYnV0ZXMiOnsic3ViamVjdCI6eyJ1c2VybmFtZSI6ImFkbWluIiwic3ViamVjdCI6ImFkbWluIn0sImNvbnRleHQiOnsiaWF0IjoxNjcxMTAyMzA5NzAyLCJhdXRoX3RpbWUiOjE2NzExMDIzMDksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiJ9fX0sImNvZGVDaGFsbGVuZ2VNZXRob2QiOiJTMjU2Iiwibm9uY2UiOiJrNTYxZlI4MjZGd092Q3JKWGc1T2FzWnI0UDQxRFJFSHlYWnRCcnlLNEljMnoxSG9CRHViRmo4YUxCcVpnNTI2Iiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiIsInNjb3BlIjoib3BlbmlkIHVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSIsImNsYWltcyI6eyJ1bm1hcHBlZENsYWltcyI6eyJ1cm46c2U6Y3VyaXR5OmNsYWltczphZG1pbjpncm91cHMiOnsic2NvcGVzIjpbInVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSJdfSwiaXNzIjp7InJlcXVpcmVkIjp0cnVlfSwic3ViIjp7InJlcXVpcmVkIjp0cnVlfSwiYXVkIjp7InJlcXVpcmVkIjp0cnVlfSwiZXhwIjp7InJlcXVpcmVkIjp0cnVlfSwiaWF0Ijp7InJlcXVpcmVkIjp0cnVlfSwiYXV0aF90aW1lIjp7InJlcXVpcmVkIjp0cnVlfSwibm9uY2UiOnsicmVxdWlyZWQiOnRydWV9LCJhY3IiOnsicmVxdWlyZWQiOnRydWV9LCJhbXIiOnsicmVxdWlyZWQiOnRydWV9LCJhenAiOnsicmVxdWlyZWQiOnRydWV9LCJuYmYiOnsicmVxdWlyZWQiOnRydWV9LCJjbGllbnRfaWQiOnsicmVxdWlyZWQiOnRydWV9LCJkZWxlZ2F0aW9uX2lkIjp7InJlcXVpcmVkIjp0cnVlfSwicHVycG9zZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNjb3BlIjp7InJlcXVpcmVkIjp0cnVlfSwianRpIjp7InJlcXVpcmVkIjp0cnVlfSwic2lkIjp7InJlcXVpcmVkIjp0cnVlfX19LCJjb2RlQ2hhbGxlbmdlIjoibFl6YkxTcTV2aWhsWnVOVTg0Tktqb2liVU9fRGxycmhhc1lUOC1OcThIRSIsInN0YXRlIjoiajFIZEJ4YkhhUWhFMVhTSVdCSklWWGp2SE1vZzNNN1hsbzdCaTVBQ3pOaU5PYmVDamwzUXpHUEQ4NVpOcXU2RiJ9fQ==	1671103860	30	1671103860	used
3cMKiYb7jgB2Q7oBmgMk9aXkSnUhkh0P	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDQ0MTUsImNyZWF0ZWQiOjE2NzExMDQxMTUsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTAyMzA5NzAyLCJhdXRoX3RpbWUiOjE2NzExMDIzMDksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjFjOTQwY2ZjLWYzZWItNGMwZi04NmRlLWVjNDg5M2VjMDk4YiIsInN1YmplY3QiOnsidXNlcm5hbWUiOiJhZG1pbiIsInN1YmplY3QiOiJhZG1pbiJ9fX0=	1671104115	300	1671104115	used
cCvoPBnssBprdgd4KFYChOgFODnwN2Ih	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDQxNDUsImNyZWF0ZWQiOjE2NzExMDQxMTUsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJhZG1pbiIsInJlZGlyZWN0VXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OS9hZG1pbi9kYXNoYm9hcmQvYXNzaXN0ZWQuaHRtbCIsImF1ZGllbmNlIjpbInVybjpzZTpjdXJpdHk6YXVkaWVuY2VzOmFkbWluOmFwaSIsImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Il0sImNsaWVudElkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJyZWRpcmVjdFVyaVByb3ZpZGVkIjp0cnVlLCJhdXRoZW50aWNhdGlvbkF0dHJpYnV0ZXMiOnsic3ViamVjdCI6eyJ1c2VybmFtZSI6ImFkbWluIiwic3ViamVjdCI6ImFkbWluIn0sImNvbnRleHQiOnsiaWF0IjoxNjcxMTAyMzA5NzAyLCJhdXRoX3RpbWUiOjE2NzExMDIzMDksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiJ9fX0sImNvZGVDaGFsbGVuZ2VNZXRob2QiOiJTMjU2Iiwibm9uY2UiOiI4VGVrSGxiVHJ6aUI5RTRDN295VGNrSGhLN3hhY2t2dkw3VUtIb2RiTnh6R2VxU0M2NEJDUG5sVUM1dklOd2E1Iiwic2lkIjoiSnBwckVSM0NlOHpYOUZtaiIsInNjb3BlIjoib3BlbmlkIHVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSIsImNsYWltcyI6eyJ1bm1hcHBlZENsYWltcyI6eyJ1cm46c2U6Y3VyaXR5OmNsYWltczphZG1pbjpncm91cHMiOnsic2NvcGVzIjpbInVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSJdfSwiaXNzIjp7InJlcXVpcmVkIjp0cnVlfSwic3ViIjp7InJlcXVpcmVkIjp0cnVlfSwiYXVkIjp7InJlcXVpcmVkIjp0cnVlfSwiZXhwIjp7InJlcXVpcmVkIjp0cnVlfSwiaWF0Ijp7InJlcXVpcmVkIjp0cnVlfSwiYXV0aF90aW1lIjp7InJlcXVpcmVkIjp0cnVlfSwibm9uY2UiOnsicmVxdWlyZWQiOnRydWV9LCJhY3IiOnsicmVxdWlyZWQiOnRydWV9LCJhbXIiOnsicmVxdWlyZWQiOnRydWV9LCJhenAiOnsicmVxdWlyZWQiOnRydWV9LCJuYmYiOnsicmVxdWlyZWQiOnRydWV9LCJjbGllbnRfaWQiOnsicmVxdWlyZWQiOnRydWV9LCJkZWxlZ2F0aW9uX2lkIjp7InJlcXVpcmVkIjp0cnVlfSwicHVycG9zZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNjb3BlIjp7InJlcXVpcmVkIjp0cnVlfSwianRpIjp7InJlcXVpcmVkIjp0cnVlfSwic2lkIjp7InJlcXVpcmVkIjp0cnVlfX19LCJjb2RlQ2hhbGxlbmdlIjoicEJFY19XQUVuMlRiVWswYURYMFNwZ2RUV0lXc1RyNkRxazUyUHBaMEFvRSIsInN0YXRlIjoiR0FRRTR6SWVkTFJwRFlzeE9SbGEzakdaSFZ5aWFEeUF4N0dqdWxiNUJ5YnAyOHRMblBZMUhJU3VnY1Y1eXJ4eiJ9fQ==	1671104115	30	1671104115	used
NM5cJrPkbEpmbPZQaOIzUfsNlV0mv6Pp	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDY2MTksImNyZWF0ZWQiOjE2NzExMDYzMTksInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTA2MzE5MTQyLCJhdXRoX3RpbWUiOjE2NzExMDYzMTksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiNHFRbDk4M3BXNTI0RDBBRCJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjFiNjFkOTQxLTA1ZTgtNDc1MS04MWUxLTc2ZjQxZTBiNzkzZiIsInN1YmplY3QiOnsidXNlcm5hbWUiOiJhZG1pbiIsInN1YmplY3QiOiJhZG1pbiJ9fX0=	1671106319	300	1671106319	used
rjDXuu6qKcznRVxx0hfsFFfN1y2mkbGd	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDYzNDksImNyZWF0ZWQiOjE2NzExMDYzMTksInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJhZG1pbiIsInJlZGlyZWN0VXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OS9hZG1pbi9kYXNoYm9hcmQvYXNzaXN0ZWQuaHRtbCIsImF1ZGllbmNlIjpbInVybjpzZTpjdXJpdHk6YXVkaWVuY2VzOmFkbWluOmFwaSIsImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Il0sImNsaWVudElkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJyZWRpcmVjdFVyaVByb3ZpZGVkIjp0cnVlLCJhdXRoZW50aWNhdGlvbkF0dHJpYnV0ZXMiOnsic3ViamVjdCI6eyJ1c2VybmFtZSI6ImFkbWluIiwic3ViamVjdCI6ImFkbWluIn0sImNvbnRleHQiOnsiaWF0IjoxNjcxMTA2MzE5MTQyLCJhdXRoX3RpbWUiOjE2NzExMDYzMTksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiNHFRbDk4M3BXNTI0RDBBRCJ9fX0sImNvZGVDaGFsbGVuZ2VNZXRob2QiOiJTMjU2Iiwibm9uY2UiOiJBaHY3b0VuNUdVV1pBT0Znd2t6aGZ1VEdwUlNYeXQ3TXFUcHNNdFFaQlNSeEJ5QVhDUjRqOVFRYW1TMG5XMFAwIiwic2lkIjoiNHFRbDk4M3BXNTI0RDBBRCIsInNjb3BlIjoib3BlbmlkIHVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSIsImNsYWltcyI6eyJ1bm1hcHBlZENsYWltcyI6eyJ1cm46c2U6Y3VyaXR5OmNsYWltczphZG1pbjpncm91cHMiOnsic2NvcGVzIjpbInVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSJdfSwiaXNzIjp7InJlcXVpcmVkIjp0cnVlfSwic3ViIjp7InJlcXVpcmVkIjp0cnVlfSwiYXVkIjp7InJlcXVpcmVkIjp0cnVlfSwiZXhwIjp7InJlcXVpcmVkIjp0cnVlfSwiaWF0Ijp7InJlcXVpcmVkIjp0cnVlfSwiYXV0aF90aW1lIjp7InJlcXVpcmVkIjp0cnVlfSwibm9uY2UiOnsicmVxdWlyZWQiOnRydWV9LCJhY3IiOnsicmVxdWlyZWQiOnRydWV9LCJhbXIiOnsicmVxdWlyZWQiOnRydWV9LCJhenAiOnsicmVxdWlyZWQiOnRydWV9LCJuYmYiOnsicmVxdWlyZWQiOnRydWV9LCJjbGllbnRfaWQiOnsicmVxdWlyZWQiOnRydWV9LCJkZWxlZ2F0aW9uX2lkIjp7InJlcXVpcmVkIjp0cnVlfSwicHVycG9zZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNjb3BlIjp7InJlcXVpcmVkIjp0cnVlfSwianRpIjp7InJlcXVpcmVkIjp0cnVlfSwic2lkIjp7InJlcXVpcmVkIjp0cnVlfX19LCJjb2RlQ2hhbGxlbmdlIjoidHp0RTdFamdnSGNTRi1USjlmWlZmbEhLV0JxNFdhelMzZ1BHWkZHbkplNCIsInN0YXRlIjoiUG9OQTR3WEQ3MEJaclY0cVpaOEFWNGNYNlhpVG1JYkRDOVd1em1mNDdNZ0ZNYmhBOGlTbTlybTNyRFZyek92QyJ9fQ==	1671106319	30	1671106319	used
4fL6mUmLeqFV3dHlIIV0Wr6boUOl3kAM	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDcxMjcsImNyZWF0ZWQiOjE2NzExMDY4MjcsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTA2MzE5MTQyLCJhdXRoX3RpbWUiOjE2NzExMDYzMTksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiNHFRbDk4M3BXNTI0RDBBRCJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjFiNjFkOTQxLTA1ZTgtNDc1MS04MWUxLTc2ZjQxZTBiNzkzZiIsInN1YmplY3QiOnsidXNlcm5hbWUiOiJhZG1pbiIsInN1YmplY3QiOiJhZG1pbiJ9fX0=	1671106827	300	1671106827	used
pJC0zDsvAI7f0LV9deauzqufBYQCnbnL	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDY4NTcsImNyZWF0ZWQiOjE2NzExMDY4MjcsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJhZG1pbiIsInJlZGlyZWN0VXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OS9hZG1pbi9kYXNoYm9hcmQvYXNzaXN0ZWQuaHRtbCIsImF1ZGllbmNlIjpbInVybjpzZTpjdXJpdHk6YXVkaWVuY2VzOmFkbWluOmFwaSIsImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Il0sImNsaWVudElkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJyZWRpcmVjdFVyaVByb3ZpZGVkIjp0cnVlLCJhdXRoZW50aWNhdGlvbkF0dHJpYnV0ZXMiOnsic3ViamVjdCI6eyJ1c2VybmFtZSI6ImFkbWluIiwic3ViamVjdCI6ImFkbWluIn0sImNvbnRleHQiOnsiaWF0IjoxNjcxMTA2MzE5MTQyLCJhdXRoX3RpbWUiOjE2NzExMDYzMTksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiNHFRbDk4M3BXNTI0RDBBRCJ9fX0sImNvZGVDaGFsbGVuZ2VNZXRob2QiOiJTMjU2Iiwibm9uY2UiOiI2OXpaZjVBZUdFcExkVWhMY0Z0NTA2T3RRUTNvU1pvTU8xZVZnaU1tT1ZCV0dYOVNBRXUya3ZSRmJvVDF5M05DIiwic2lkIjoiNHFRbDk4M3BXNTI0RDBBRCIsInNjb3BlIjoib3BlbmlkIHVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSIsImNsYWltcyI6eyJ1bm1hcHBlZENsYWltcyI6eyJ1cm46c2U6Y3VyaXR5OmNsYWltczphZG1pbjpncm91cHMiOnsic2NvcGVzIjpbInVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSJdfSwiaXNzIjp7InJlcXVpcmVkIjp0cnVlfSwic3ViIjp7InJlcXVpcmVkIjp0cnVlfSwiYXVkIjp7InJlcXVpcmVkIjp0cnVlfSwiZXhwIjp7InJlcXVpcmVkIjp0cnVlfSwiaWF0Ijp7InJlcXVpcmVkIjp0cnVlfSwiYXV0aF90aW1lIjp7InJlcXVpcmVkIjp0cnVlfSwibm9uY2UiOnsicmVxdWlyZWQiOnRydWV9LCJhY3IiOnsicmVxdWlyZWQiOnRydWV9LCJhbXIiOnsicmVxdWlyZWQiOnRydWV9LCJhenAiOnsicmVxdWlyZWQiOnRydWV9LCJuYmYiOnsicmVxdWlyZWQiOnRydWV9LCJjbGllbnRfaWQiOnsicmVxdWlyZWQiOnRydWV9LCJkZWxlZ2F0aW9uX2lkIjp7InJlcXVpcmVkIjp0cnVlfSwicHVycG9zZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNjb3BlIjp7InJlcXVpcmVkIjp0cnVlfSwianRpIjp7InJlcXVpcmVkIjp0cnVlfSwic2lkIjp7InJlcXVpcmVkIjp0cnVlfX19LCJjb2RlQ2hhbGxlbmdlIjoiZllWLVRSZF9WSUswOUNaUEFmZW9zMUZJSWRsa0ZVSW5LWmI2WVo1Tk84dyIsInN0YXRlIjoiOWtzOVVSQXJWSFRUU1dnaUYxdWVqRmw2TzdNb0U4OFBlN0g5YXg1NTRBRzU3akV5QnIxVlBiS3B0MkNZb1RNOSJ9fQ==	1671106827	30	1671106827	used
IgstCpddkU7HogTyBIIe14a2gy8Oylyc	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDcyMjgsImNyZWF0ZWQiOjE2NzExMDY5MjgsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTA2MzE5MTQyLCJhdXRoX3RpbWUiOjE2NzExMDYzMTksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiNHFRbDk4M3BXNTI0RDBBRCJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjFiNjFkOTQxLTA1ZTgtNDc1MS04MWUxLTc2ZjQxZTBiNzkzZiIsInN1YmplY3QiOnsidXNlcm5hbWUiOiJhZG1pbiIsInN1YmplY3QiOiJhZG1pbiJ9fX0=	1671106928	300	1671106928	used
aRz7EeJGXJg37CmFbqVHLcoa10UfKK7h	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDY5NTgsImNyZWF0ZWQiOjE2NzExMDY5MjgsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJhZG1pbiIsInJlZGlyZWN0VXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OS9hZG1pbi9kYXNoYm9hcmQvYXNzaXN0ZWQuaHRtbCIsImF1ZGllbmNlIjpbInVybjpzZTpjdXJpdHk6YXVkaWVuY2VzOmFkbWluOmFwaSIsImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Il0sImNsaWVudElkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJyZWRpcmVjdFVyaVByb3ZpZGVkIjp0cnVlLCJhdXRoZW50aWNhdGlvbkF0dHJpYnV0ZXMiOnsic3ViamVjdCI6eyJ1c2VybmFtZSI6ImFkbWluIiwic3ViamVjdCI6ImFkbWluIn0sImNvbnRleHQiOnsiaWF0IjoxNjcxMTA2MzE5MTQyLCJhdXRoX3RpbWUiOjE2NzExMDYzMTksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiNHFRbDk4M3BXNTI0RDBBRCJ9fX0sImNvZGVDaGFsbGVuZ2VNZXRob2QiOiJTMjU2Iiwibm9uY2UiOiJsYkI1THNWdk9VbkNHTmVMd1RoYzhzdGRSak02VDFPM1VTUFN3NUZmVXRCZVBHV1lYdXd6TzB6QzZISGJEZFU5Iiwic2lkIjoiNHFRbDk4M3BXNTI0RDBBRCIsInNjb3BlIjoib3BlbmlkIHVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSIsImNsYWltcyI6eyJ1bm1hcHBlZENsYWltcyI6eyJ1cm46c2U6Y3VyaXR5OmNsYWltczphZG1pbjpncm91cHMiOnsic2NvcGVzIjpbInVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaSJdfSwiaXNzIjp7InJlcXVpcmVkIjp0cnVlfSwic3ViIjp7InJlcXVpcmVkIjp0cnVlfSwiYXVkIjp7InJlcXVpcmVkIjp0cnVlfSwiZXhwIjp7InJlcXVpcmVkIjp0cnVlfSwiaWF0Ijp7InJlcXVpcmVkIjp0cnVlfSwiYXV0aF90aW1lIjp7InJlcXVpcmVkIjp0cnVlfSwibm9uY2UiOnsicmVxdWlyZWQiOnRydWV9LCJhY3IiOnsicmVxdWlyZWQiOnRydWV9LCJhbXIiOnsicmVxdWlyZWQiOnRydWV9LCJhenAiOnsicmVxdWlyZWQiOnRydWV9LCJuYmYiOnsicmVxdWlyZWQiOnRydWV9LCJjbGllbnRfaWQiOnsicmVxdWlyZWQiOnRydWV9LCJkZWxlZ2F0aW9uX2lkIjp7InJlcXVpcmVkIjp0cnVlfSwicHVycG9zZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNjb3BlIjp7InJlcXVpcmVkIjp0cnVlfSwianRpIjp7InJlcXVpcmVkIjp0cnVlfSwic2lkIjp7InJlcXVpcmVkIjp0cnVlfX19LCJjb2RlQ2hhbGxlbmdlIjoicWxXcWdUMzhWSjRFakhodUl2d0dXZE56aEphd2M4MUpaRjlyQWtWYU53byIsInN0YXRlIjoiclVYTTd2REJHR1BXTjBKSGlzd05YZmQ4WG9sTFFDNkdoRW12YXcwUFNQd1lOR01OTDE5ejRnb2xKcFhwRGJpVyJ9fQ==	1671106928	30	1671106928	used
eLGHIm6CsGehRvFpvBlVrbFzVdvZAQEU	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDczMTIsImNyZWF0ZWQiOjE2NzExMDcwMTIsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA3MDEyLCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJWa0hMRTN1OWs3cm9Qelp5In19LCJhdWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2Vzc2lvbklkIjoiMWI2MWQ5NDEtMDVlOC00NzUxLTgxZTEtNzZmNDFlMGI3OTNmIiwic3ViamVjdCI6eyJhY2NvdW50SWQiOiIzMWUwNzRmNC03YzczLTExZWQtYmFjMy0wMjQyYWMxYTAwMDIiLCJ1c2VyTmFtZSI6ImpvaG5kb2UiLCJzdWJqZWN0Ijoiam9obmRvZSJ9fX0=	1671107012	300	1671107012	used
2HB41lLjt8DMtAhMKmpJ0hqS7knEUnOX	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDcwNDIsImNyZWF0ZWQiOjE2NzExMDcwMTIsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7ImFjY291bnRJZCI6IjMxZTA3NGY0LTdjNzMtMTFlZC1iYWMzLTAyNDJhYzFhMDAwMiIsInVzZXJOYW1lIjoiam9obmRvZSIsInN1YmplY3QiOiJqb2huZG9lIn0sImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA3MDEyLCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJWa0hMRTN1OWs3cm9Qelp5In19fSwiY29kZUNoYWxsZW5nZU1ldGhvZCI6IlMyNTYiLCJub25jZSI6InZCTWZ4ZDA1OHV2SHgwd0tsUW13REJjck9aUncxRWVidUloeEFjVDluaGpsaFNVbkR0VTBYcGpRRWpuMzhZQ1EiLCJzaWQiOiJWa0hMRTN1OWs3cm9Qelp5Iiwic2NvcGUiOiJvcGVuaWQgdXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIiwiY2xhaW1zIjp7InVubWFwcGVkQ2xhaW1zIjp7InVybjpzZTpjdXJpdHk6Y2xhaW1zOmFkbWluOmdyb3VwcyI6eyJzY29wZXMiOlsidXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIl19LCJpc3MiOnsicmVxdWlyZWQiOnRydWV9LCJzdWIiOnsicmVxdWlyZWQiOnRydWV9LCJhdWQiOnsicmVxdWlyZWQiOnRydWV9LCJleHAiOnsicmVxdWlyZWQiOnRydWV9LCJpYXQiOnsicmVxdWlyZWQiOnRydWV9LCJhdXRoX3RpbWUiOnsicmVxdWlyZWQiOnRydWV9LCJub25jZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFjciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFtciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF6cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5iZiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImNsaWVudF9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImRlbGVnYXRpb25faWQiOnsicmVxdWlyZWQiOnRydWV9LCJwdXJwb3NlIjp7InJlcXVpcmVkIjp0cnVlfSwic2NvcGUiOnsicmVxdWlyZWQiOnRydWV9LCJqdGkiOnsicmVxdWlyZWQiOnRydWV9LCJzaWQiOnsicmVxdWlyZWQiOnRydWV9fX0sImNvZGVDaGFsbGVuZ2UiOiJkaUhtX2wzWDJWQ3NZSUxoU1FkU1VuczNSQnFwdHViby1lZVZITTZZVHAwIiwic3RhdGUiOiJkRm1lcERMenE0bWFpTkZaOFNjalNUcWYwa0N4b3BFdE9RNGExaVEza0xDMFNNUjBWeVM4ZXhnZHNIRTlPU2dMIn19	1671107012	30	1671107013	used
Vre7fEDZ0HlcGja9biSPfKVptAvO5iJV	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDczNTksImNyZWF0ZWQiOjE2NzExMDcwNTksInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA3MDEyLCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJWa0hMRTN1OWs3cm9Qelp5In19LCJhdWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2Vzc2lvbklkIjoiMWI2MWQ5NDEtMDVlOC00NzUxLTgxZTEtNzZmNDFlMGI3OTNmIiwic3ViamVjdCI6eyJhY2NvdW50SWQiOiIzMWUwNzRmNC03YzczLTExZWQtYmFjMy0wMjQyYWMxYTAwMDIiLCJ1c2VyTmFtZSI6ImpvaG5kb2UiLCJzdWJqZWN0Ijoiam9obmRvZSJ9fX0=	1671107059	300	1671107059	used
4zTMh1Pw4pCRtxQ0R8iVjGWnREB3Q8ga	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDcwODksImNyZWF0ZWQiOjE2NzExMDcwNTksInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7ImFjY291bnRJZCI6IjMxZTA3NGY0LTdjNzMtMTFlZC1iYWMzLTAyNDJhYzFhMDAwMiIsInVzZXJOYW1lIjoiam9obmRvZSIsInN1YmplY3QiOiJqb2huZG9lIn0sImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA3MDEyLCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJWa0hMRTN1OWs3cm9Qelp5In19fSwiY29kZUNoYWxsZW5nZU1ldGhvZCI6IlMyNTYiLCJub25jZSI6IkZIN1NqbWpGVkE0QWxWZVVjNGU4b2N0VzlENkhidUtIamxvY00xMW50bzNyejc2VTZ4OWdKTUhQQ2ZjSDFOQmQiLCJzaWQiOiJWa0hMRTN1OWs3cm9Qelp5Iiwic2NvcGUiOiJvcGVuaWQgdXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIiwiY2xhaW1zIjp7InVubWFwcGVkQ2xhaW1zIjp7InVybjpzZTpjdXJpdHk6Y2xhaW1zOmFkbWluOmdyb3VwcyI6eyJzY29wZXMiOlsidXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIl19LCJpc3MiOnsicmVxdWlyZWQiOnRydWV9LCJzdWIiOnsicmVxdWlyZWQiOnRydWV9LCJhdWQiOnsicmVxdWlyZWQiOnRydWV9LCJleHAiOnsicmVxdWlyZWQiOnRydWV9LCJpYXQiOnsicmVxdWlyZWQiOnRydWV9LCJhdXRoX3RpbWUiOnsicmVxdWlyZWQiOnRydWV9LCJub25jZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFjciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFtciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF6cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5iZiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImNsaWVudF9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImRlbGVnYXRpb25faWQiOnsicmVxdWlyZWQiOnRydWV9LCJwdXJwb3NlIjp7InJlcXVpcmVkIjp0cnVlfSwic2NvcGUiOnsicmVxdWlyZWQiOnRydWV9LCJqdGkiOnsicmVxdWlyZWQiOnRydWV9LCJzaWQiOnsicmVxdWlyZWQiOnRydWV9fX0sImNvZGVDaGFsbGVuZ2UiOiJpSU43d3R3QUxjSWxocWVtQ01HakQxbVpPOHh6bWItN2VnUFRIcUR4NVhVIiwic3RhdGUiOiJuU1pjN0lrVGtUWUlQR1V6VWtCZXVGcUUyeVF6TG9xdk9hRjNVdnByMXc1aUJmWWtOV2ZwekJmVWVJU3FIam9BIn19	1671107059	30	1671107059	used
tWoVtTrHqb9V6QM2nyTuhcDddfdFGR6Y	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDkzOTcsImNyZWF0ZWQiOjE2NzExMDkwOTcsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA5MDk3LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJMcXJrQzBWWU0xTnA2eHJqIn19LCJhdWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2Vzc2lvbklkIjoiZjM1N2M4Y2MtOTY1Yi00ZDk0LWE3NGYtNjFhOTg3NGQ3YmE3Iiwic3ViamVjdCI6eyJhY2NvdW50SWQiOiIzMWUwNzRmNC03YzczLTExZWQtYmFjMy0wMjQyYWMxYTAwMDIiLCJ1c2VyTmFtZSI6ImpvaG5kb2UiLCJzdWJqZWN0Ijoiam9obmRvZSJ9fX0=	1671109097	300	1671109097	used
5POANq3012VEgdHGtNFDtqgn6bbhVMY4	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDkxMjcsImNyZWF0ZWQiOjE2NzExMDkwOTcsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7ImFjY291bnRJZCI6IjMxZTA3NGY0LTdjNzMtMTFlZC1iYWMzLTAyNDJhYzFhMDAwMiIsInVzZXJOYW1lIjoiam9obmRvZSIsInN1YmplY3QiOiJqb2huZG9lIn0sImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA5MDk3LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJMcXJrQzBWWU0xTnA2eHJqIn19fSwiY29kZUNoYWxsZW5nZU1ldGhvZCI6IlMyNTYiLCJub25jZSI6IkNCdEtmYlRTU3pRRVg2UXZQbzI3RHZjZEl1Tkl6QzRHMTB1ZTRNaDRyd3M2eWo0U21mb0pUR0h0S2FIS3A4c1ciLCJzaWQiOiJMcXJrQzBWWU0xTnA2eHJqIiwic2NvcGUiOiJvcGVuaWQgdXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIiwiY2xhaW1zIjp7InVubWFwcGVkQ2xhaW1zIjp7InVybjpzZTpjdXJpdHk6Y2xhaW1zOmFkbWluOmdyb3VwcyI6eyJzY29wZXMiOlsidXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIl19LCJpc3MiOnsicmVxdWlyZWQiOnRydWV9LCJzdWIiOnsicmVxdWlyZWQiOnRydWV9LCJhdWQiOnsicmVxdWlyZWQiOnRydWV9LCJleHAiOnsicmVxdWlyZWQiOnRydWV9LCJpYXQiOnsicmVxdWlyZWQiOnRydWV9LCJhdXRoX3RpbWUiOnsicmVxdWlyZWQiOnRydWV9LCJub25jZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFjciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFtciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF6cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5iZiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImNsaWVudF9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImRlbGVnYXRpb25faWQiOnsicmVxdWlyZWQiOnRydWV9LCJwdXJwb3NlIjp7InJlcXVpcmVkIjp0cnVlfSwic2NvcGUiOnsicmVxdWlyZWQiOnRydWV9LCJqdGkiOnsicmVxdWlyZWQiOnRydWV9LCJzaWQiOnsicmVxdWlyZWQiOnRydWV9fX0sImNvZGVDaGFsbGVuZ2UiOiJRMzJxNms5UWxGU2tSaG16XzZERy1Ob1BBZkk2UmhJSnl1MTVabXZVNElZIiwic3RhdGUiOiI4aWdjakxFeTFUTFdVUGEyVWVyS1FpTGdjdjR0R1VUWUU2aFV3R1Z2WGlKNXZxQlZGU3JNNXk5VWJleEZ0UVhqIn19	1671109097	30	1671109097	used
d4mzngRyjN2OP7uuqVEbQDRZoNa3Y3RN	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDk0NTcsImNyZWF0ZWQiOjE2NzExMDkxNTcsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA5MTU3LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJzeGNSTzNYNXJyUHZSbU5GIn19LCJhdWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2Vzc2lvbklkIjoiZjM1N2M4Y2MtOTY1Yi00ZDk0LWE3NGYtNjFhOTg3NGQ3YmE3Iiwic3ViamVjdCI6eyJhY2NvdW50SWQiOiIzMWUwNzRmNC03YzczLTExZWQtYmFjMy0wMjQyYWMxYTAwMDIiLCJ1c2VyTmFtZSI6ImpvaG5kb2UiLCJzdWJqZWN0Ijoiam9obmRvZSJ9fX0=	1671109157	300	1671109157	used
rJi7zXfQULtx3xlCSMk19REE6ntUpBuK	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDkxODcsImNyZWF0ZWQiOjE2NzExMDkxNTcsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7ImFjY291bnRJZCI6IjMxZTA3NGY0LTdjNzMtMTFlZC1iYWMzLTAyNDJhYzFhMDAwMiIsInVzZXJOYW1lIjoiam9obmRvZSIsInN1YmplY3QiOiJqb2huZG9lIn0sImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA5MTU3LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJzeGNSTzNYNXJyUHZSbU5GIn19fSwiY29kZUNoYWxsZW5nZU1ldGhvZCI6IlMyNTYiLCJub25jZSI6IllySmhqVE1JTUZ0Nk52ZWRRUE45eVBGZ0d0VWhHR1RVM1cyQWtGNURmM3loOUFKNm9RdldzcUV5d2NMbXpXR0EiLCJzaWQiOiJzeGNSTzNYNXJyUHZSbU5GIiwic2NvcGUiOiJvcGVuaWQgdXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIiwiY2xhaW1zIjp7InVubWFwcGVkQ2xhaW1zIjp7InVybjpzZTpjdXJpdHk6Y2xhaW1zOmFkbWluOmdyb3VwcyI6eyJzY29wZXMiOlsidXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIl19LCJpc3MiOnsicmVxdWlyZWQiOnRydWV9LCJzdWIiOnsicmVxdWlyZWQiOnRydWV9LCJhdWQiOnsicmVxdWlyZWQiOnRydWV9LCJleHAiOnsicmVxdWlyZWQiOnRydWV9LCJpYXQiOnsicmVxdWlyZWQiOnRydWV9LCJhdXRoX3RpbWUiOnsicmVxdWlyZWQiOnRydWV9LCJub25jZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFjciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFtciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF6cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5iZiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImNsaWVudF9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImRlbGVnYXRpb25faWQiOnsicmVxdWlyZWQiOnRydWV9LCJwdXJwb3NlIjp7InJlcXVpcmVkIjp0cnVlfSwic2NvcGUiOnsicmVxdWlyZWQiOnRydWV9LCJqdGkiOnsicmVxdWlyZWQiOnRydWV9LCJzaWQiOnsicmVxdWlyZWQiOnRydWV9fX0sImNvZGVDaGFsbGVuZ2UiOiJYandYQVVTaGxfdHg5cnNUaFphVkZkbThZU2d0ek1pUUFENldkT0x1VEZvIiwic3RhdGUiOiJXY0RjSEJhbzdHRXJwcHRDNnpVMFJKd3RnOUhmcERLRWJLSWdxQjdJT2dKWmk3WHdlYVg3TFh2eU5wQ3hGdzB0In19	1671109157	30	1671109157	used
H1ZwWrlhhIoqzYkuqNuTevFwLB1KYZjR	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDk0NzIsImNyZWF0ZWQiOjE2NzExMDkxNzIsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA5MTU3LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJzeGNSTzNYNXJyUHZSbU5GIn19LCJhdWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2Vzc2lvbklkIjoiZjM1N2M4Y2MtOTY1Yi00ZDk0LWE3NGYtNjFhOTg3NGQ3YmE3Iiwic3ViamVjdCI6eyJhY2NvdW50SWQiOiIzMWUwNzRmNC03YzczLTExZWQtYmFjMy0wMjQyYWMxYTAwMDIiLCJ1c2VyTmFtZSI6ImpvaG5kb2UiLCJzdWJqZWN0Ijoiam9obmRvZSJ9fX0=	1671109172	300	1671109172	used
3ePdHyggL2R7AfbF4JQkzLCFA2e4gqjA	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDkyMDIsImNyZWF0ZWQiOjE2NzExMDkxNzIsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7ImFjY291bnRJZCI6IjMxZTA3NGY0LTdjNzMtMTFlZC1iYWMzLTAyNDJhYzFhMDAwMiIsInVzZXJOYW1lIjoiam9obmRvZSIsInN1YmplY3QiOiJqb2huZG9lIn0sImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA5MTU3LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJzeGNSTzNYNXJyUHZSbU5GIn19fSwiY29kZUNoYWxsZW5nZU1ldGhvZCI6IlMyNTYiLCJub25jZSI6IlF3U1Y3TkQ4VWFHQkh6RVdtcHBsY1NFQUpnaUJjb0s4OWN0aVlCckVoc0xWVDVISHNSVXNHODdqc29GNkNaN2oiLCJzaWQiOiJzeGNSTzNYNXJyUHZSbU5GIiwic2NvcGUiOiJvcGVuaWQgdXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIiwiY2xhaW1zIjp7InVubWFwcGVkQ2xhaW1zIjp7InVybjpzZTpjdXJpdHk6Y2xhaW1zOmFkbWluOmdyb3VwcyI6eyJzY29wZXMiOlsidXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIl19LCJpc3MiOnsicmVxdWlyZWQiOnRydWV9LCJzdWIiOnsicmVxdWlyZWQiOnRydWV9LCJhdWQiOnsicmVxdWlyZWQiOnRydWV9LCJleHAiOnsicmVxdWlyZWQiOnRydWV9LCJpYXQiOnsicmVxdWlyZWQiOnRydWV9LCJhdXRoX3RpbWUiOnsicmVxdWlyZWQiOnRydWV9LCJub25jZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFjciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFtciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF6cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5iZiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImNsaWVudF9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImRlbGVnYXRpb25faWQiOnsicmVxdWlyZWQiOnRydWV9LCJwdXJwb3NlIjp7InJlcXVpcmVkIjp0cnVlfSwic2NvcGUiOnsicmVxdWlyZWQiOnRydWV9LCJqdGkiOnsicmVxdWlyZWQiOnRydWV9LCJzaWQiOnsicmVxdWlyZWQiOnRydWV9fX0sImNvZGVDaGFsbGVuZ2UiOiJyQm9rQjRGeTNnSy1HWmJVM2NNYjhmVGgxX3JaSVhMUUJjeDBTbFFsRWlzIiwic3RhdGUiOiI5TmQzcjc5VlhBSlJCQ1h5NGZpaW9YMnFIbHJDSEZQWFd5M1ZWaWFsOHQ3QXdTRDVrSU1IdTBXbHVDQmxrR29pIn19	1671109172	30	1671109173	used
O4Nn62VzXrOo7m2MpDBrTJubtpw0TDGP	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDk0OTQsImNyZWF0ZWQiOjE2NzExMDkxOTQsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA5MTk0LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJ0bDBuTlFUMVgxYnJwNU9xIn19LCJhdWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2Vzc2lvbklkIjoiZjM1N2M4Y2MtOTY1Yi00ZDk0LWE3NGYtNjFhOTg3NGQ3YmE3Iiwic3ViamVjdCI6eyJhY2NvdW50SWQiOiIzMWUwNzRmNC03YzczLTExZWQtYmFjMy0wMjQyYWMxYTAwMDIiLCJ1c2VyTmFtZSI6ImpvaG5kb2UiLCJzdWJqZWN0Ijoiam9obmRvZSJ9fX0=	1671109194	300	1671109194	used
ZslJMOPGg0jEFuPpyH9ESrbTr8DqFvLK	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDkyMjQsImNyZWF0ZWQiOjE2NzExMDkxOTQsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7ImFjY291bnRJZCI6IjMxZTA3NGY0LTdjNzMtMTFlZC1iYWMzLTAyNDJhYzFhMDAwMiIsInVzZXJOYW1lIjoiam9obmRvZSIsInN1YmplY3QiOiJqb2huZG9lIn0sImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA5MTk0LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJ0bDBuTlFUMVgxYnJwNU9xIn19fSwiY29kZUNoYWxsZW5nZU1ldGhvZCI6IlMyNTYiLCJub25jZSI6ImliVDBWSnUxRXF2Vmp1amVWZHplbUVTSzBLQXRHQzNsdHRBekJWUUc3VXJxSnhka2RVQ1hjNGZ1V0pqRUtLVGYiLCJzaWQiOiJ0bDBuTlFUMVgxYnJwNU9xIiwic2NvcGUiOiJvcGVuaWQgdXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIiwiY2xhaW1zIjp7InVubWFwcGVkQ2xhaW1zIjp7InVybjpzZTpjdXJpdHk6Y2xhaW1zOmFkbWluOmdyb3VwcyI6eyJzY29wZXMiOlsidXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIl19LCJpc3MiOnsicmVxdWlyZWQiOnRydWV9LCJzdWIiOnsicmVxdWlyZWQiOnRydWV9LCJhdWQiOnsicmVxdWlyZWQiOnRydWV9LCJleHAiOnsicmVxdWlyZWQiOnRydWV9LCJpYXQiOnsicmVxdWlyZWQiOnRydWV9LCJhdXRoX3RpbWUiOnsicmVxdWlyZWQiOnRydWV9LCJub25jZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFjciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFtciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF6cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5iZiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImNsaWVudF9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImRlbGVnYXRpb25faWQiOnsicmVxdWlyZWQiOnRydWV9LCJwdXJwb3NlIjp7InJlcXVpcmVkIjp0cnVlfSwic2NvcGUiOnsicmVxdWlyZWQiOnRydWV9LCJqdGkiOnsicmVxdWlyZWQiOnRydWV9LCJzaWQiOnsicmVxdWlyZWQiOnRydWV9fX0sImNvZGVDaGFsbGVuZ2UiOiJZUWVPaUM3YTZaTURYeFFTQk1aaU1SM0Q0QlhiOVpBSmtzMWhsLXVkYkIwIiwic3RhdGUiOiIzOFNrR2l5SEg2WEJ6QTdaRXU2QjNDRklxd0RPMmJNWFBQWk1GcmRKUjkyaW5VRGhoSVNBYW5mQ0NwWXRoTjZtIn19	1671109194	30	1671109194	used
o5poQWEF9woHoAtKiD7d0vo0jtaj8MkF	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDk1MjYsImNyZWF0ZWQiOjE2NzExMDkyMjYsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA5MjI2LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJYNkNmTWZDVk5OdGZOWTAwIn19LCJhdWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2Vzc2lvbklkIjoiZjM1N2M4Y2MtOTY1Yi00ZDk0LWE3NGYtNjFhOTg3NGQ3YmE3Iiwic3ViamVjdCI6eyJhY2NvdW50SWQiOiIzMWUwNzRmNC03YzczLTExZWQtYmFjMy0wMjQyYWMxYTAwMDIiLCJ1c2VyTmFtZSI6ImpvaG5kb2UiLCJzdWJqZWN0Ijoiam9obmRvZSJ9fX0=	1671109226	300	1671109227	used
evOcxSx4RL6kuL2rfW4sT0sfrkPATABS	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDkyNTcsImNyZWF0ZWQiOjE2NzExMDkyMjcsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7ImFjY291bnRJZCI6IjMxZTA3NGY0LTdjNzMtMTFlZC1iYWMzLTAyNDJhYzFhMDAwMiIsInVzZXJOYW1lIjoiam9obmRvZSIsInN1YmplY3QiOiJqb2huZG9lIn0sImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA5MjI2LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJYNkNmTWZDVk5OdGZOWTAwIn19fSwiY29kZUNoYWxsZW5nZU1ldGhvZCI6IlMyNTYiLCJub25jZSI6ImFYTEJlaWpYTlZHbVNoWFBDRmtTSzhEeTBVM09GdVhHOXlpeHFuRjhJUnRIV3hyM0hzR3dxUjZNVUJxNFN5VEQiLCJzaWQiOiJYNkNmTWZDVk5OdGZOWTAwIiwic2NvcGUiOiJvcGVuaWQgdXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIiwiY2xhaW1zIjp7InVubWFwcGVkQ2xhaW1zIjp7InVybjpzZTpjdXJpdHk6Y2xhaW1zOmFkbWluOmdyb3VwcyI6eyJzY29wZXMiOlsidXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIl19LCJpc3MiOnsicmVxdWlyZWQiOnRydWV9LCJzdWIiOnsicmVxdWlyZWQiOnRydWV9LCJhdWQiOnsicmVxdWlyZWQiOnRydWV9LCJleHAiOnsicmVxdWlyZWQiOnRydWV9LCJpYXQiOnsicmVxdWlyZWQiOnRydWV9LCJhdXRoX3RpbWUiOnsicmVxdWlyZWQiOnRydWV9LCJub25jZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFjciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFtciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF6cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5iZiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImNsaWVudF9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImRlbGVnYXRpb25faWQiOnsicmVxdWlyZWQiOnRydWV9LCJwdXJwb3NlIjp7InJlcXVpcmVkIjp0cnVlfSwic2NvcGUiOnsicmVxdWlyZWQiOnRydWV9LCJqdGkiOnsicmVxdWlyZWQiOnRydWV9LCJzaWQiOnsicmVxdWlyZWQiOnRydWV9fX0sImNvZGVDaGFsbGVuZ2UiOiJzaUVNYjFfck82S1c5Ty12cFlHYVdwVGUxcmlvN2lzaXRaSno3LXZUV0dFIiwic3RhdGUiOiJxbGNsc3NzRmhHV2lhTUxGc0VNakFuSGZpbUxWeWVZSDYyWk12WUhCNDVucVZCdVhva2hZQTRoeVc0U3ptaG91In19	1671109227	30	1671109227	used
OWW0FHkg8QS4TcGsokdMDYGXPhVAhH2X	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDk2NTIsImNyZWF0ZWQiOjE2NzExMDkzNTIsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA5MzUyLCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJ6Q1RaVVAxT1lybTRLUjVnIn19LCJhdWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2Vzc2lvbklkIjoiYTM2ZGFkMjYtMzVhZC00Y2Y0LTkwZGEtYmVlMWVhMTQxODdkIiwic3ViamVjdCI6eyJhY2NvdW50SWQiOiIzMWUwNzRmNC03YzczLTExZWQtYmFjMy0wMjQyYWMxYTAwMDIiLCJ1c2VyTmFtZSI6ImpvaG5kb2UiLCJzdWJqZWN0Ijoiam9obmRvZSJ9fX0=	1671109352	300	1671109352	used
V1v7uPKbayyDWzxS2jHfHGB8DZdy8c0j	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExMDkzODIsImNyZWF0ZWQiOjE2NzExMDkzNTIsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7ImFjY291bnRJZCI6IjMxZTA3NGY0LTdjNzMtMTFlZC1iYWMzLTAyNDJhYzFhMDAwMiIsInVzZXJOYW1lIjoiam9obmRvZSIsInN1YmplY3QiOiJqb2huZG9lIn0sImNvbnRleHQiOnsiYXV0aF90aW1lIjoxNjcxMTA5MzUyLCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJ6Q1RaVVAxT1lybTRLUjVnIn19fSwiY29kZUNoYWxsZW5nZU1ldGhvZCI6IlMyNTYiLCJub25jZSI6Ik9TZzl5Z2FnNjdjbmFiQmM5N3FyUWZVZWhjbmQ1SnAyNjJ4aG5WTkY5SVliN05NTTZLT2g5dlNzNVF1U0l0NEYiLCJzaWQiOiJ6Q1RaVVAxT1lybTRLUjVnIiwic2NvcGUiOiJvcGVuaWQgdXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIiwiY2xhaW1zIjp7InVubWFwcGVkQ2xhaW1zIjp7InVybjpzZTpjdXJpdHk6Y2xhaW1zOmFkbWluOmdyb3VwcyI6eyJzY29wZXMiOlsidXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIl19LCJpc3MiOnsicmVxdWlyZWQiOnRydWV9LCJzdWIiOnsicmVxdWlyZWQiOnRydWV9LCJhdWQiOnsicmVxdWlyZWQiOnRydWV9LCJleHAiOnsicmVxdWlyZWQiOnRydWV9LCJpYXQiOnsicmVxdWlyZWQiOnRydWV9LCJhdXRoX3RpbWUiOnsicmVxdWlyZWQiOnRydWV9LCJub25jZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFjciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFtciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF6cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5iZiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImNsaWVudF9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImRlbGVnYXRpb25faWQiOnsicmVxdWlyZWQiOnRydWV9LCJwdXJwb3NlIjp7InJlcXVpcmVkIjp0cnVlfSwic2NvcGUiOnsicmVxdWlyZWQiOnRydWV9LCJqdGkiOnsicmVxdWlyZWQiOnRydWV9LCJzaWQiOnsicmVxdWlyZWQiOnRydWV9fX0sImNvZGVDaGFsbGVuZ2UiOiJWRjdUSEx6UU4wQjJXX3dIajc1NTFfdUZJUVhNUElTWE1wbk9NTXhDQXV3Iiwic3RhdGUiOiJlOGhrbXZ3SnRyV2huQ2lDUzIzak1WRWpRTmFRUEVud3NqZXNOeW4ybnBlNHZNQzFKeUFRcUZXc3dTWlFLUURBIn19	1671109352	30	1671109352	used
\.


--
-- Data for Name: sessions; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.sessions (id, session_data, expires) FROM stdin;
1c940cfc-f3eb-4c0f-86de-ec4893ec098b	rO0ABXNyADVjb20uZ29vZ2xlLmNvbW1vbi5jb2xsZWN0LkltbXV0YWJsZU1hcCRTZXJpYWxpemVkRm9ybQAAAAAAAAAAAgACTAAEa2V5c3QAEkxqYXZhL2xhbmcvT2JqZWN0O0wABnZhbHVlc3EAfgABeHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAMdAARaHRtbGZvcm0uYXR0ZW1wdHN0ABZfYXV0aG4tcmVxLmZvcmNlLWF1dGhudAAZQVVUSE5fSU5URVJNRURJQVRFX1JFU1VMVHQAHl9hdXRobi1yZXEuc2VydmljZS1wcm92aWRlci1pZHQAEVJFU1VNQUJMRV9SRVFVRVNUdAAOX19hdXRoblJlcXVlc3R0AB1wcm90b2NvbFJlcXVlc3RUcmFuc2Zvcm1lcjppZHQAIVNUQVJUX0FVVEhOX1RJTUVfQVNfRVBPQ0hfU0VDT05EU3QAG29yaWdpbmFsLWF1dGh6LXF1ZXJ5LXN0cmluZ3QAFndlYi5yZXF1ZXN0LWZvcl9vcmlnaW50ABtvcmlnaW5hbC1hdXRobi1xdWVyeS1zdHJpbmd0AA5fdHJhbnNhY3Rpb25JZHVxAH4AAwAAAAxzcgA8c2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLnNlc3Npb24uSW50ZXJuYWxTZXNzaW9uJFNlc3Npb25EYXRha/zdOk3KalwCAAFMAAZfdmFsdWV0AClMY29tL2dvb2dsZS9jb21tb24vY29sbGVjdC9JbW11dGFibGVMaXN0O3hwc3IANmNvbS5nb29nbGUuY29tbW9uLmNvbGxlY3QuSW1tdXRhYmxlTGlzdCRTZXJpYWxpemVkRm9ybQAAAAAAAAAAAgABWwAIZWxlbWVudHN0ABNbTGphdmEvbGFuZy9PYmplY3Q7eHB1cQB+AAMAAAABc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAAFzcQB+ABJzcQB+ABV1cQB+AAMAAAABc3IAEWphdmEubGFuZy5Cb29sZWFuzSBygNWc+u4CAAFaAAV2YWx1ZXhwAHNxAH4AEnNxAH4AFXVxAH4AAwAAAABzcQB+ABJzcQB+ABV1cQB+AAMAAAABc3IATXNlLmN1cml0eS5pZGVudGl0eXNlcnZlci5wbHVnaW4ucHJvdG9jb2wuc2ltcGxlYXBpLlNpbXBsZUFwaVNlcnZpY2VQcm92aWRlcklkt55a24rmGB4CAAJaABdfaXNPQXV0aFNlcnZpY2VQcm92aWRlckwACV9jbGllbnRJZHQANUxzZS9jdXJpdHkvaWRlbnRpdHlzZXJ2ZXIvZGF0YS9kb21haW4vb2F1dGgvQ2xpZW50SWQ7eHIAPHNlLmN1cml0eS5pZGVudGl0eXNlcnZlci5wbHVnaW5zLnByb3RvY29scy5TZXJ2aWNlUHJvdmlkZXJJZLCqJHYgMJVyAgACTAAKX3Byb2ZpbGVJZHQAEkxqYXZhL2xhbmcvU3RyaW5nO0wABl92YWx1ZXEAfgAqeHB0AA10b2tlbi1zZXJ2aWNldAAgZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQBc3IAM3NlLmN1cml0eS5pZGVudGl0eXNlcnZlci5kYXRhLmRvbWFpbi5vYXV0aC5DbGllbnRJZOl3K4MOWnwfAgADWgAGX3ZhbGlkTAAJX2NsaWVudElkcQB+ACpMABBfZXN0YWJsaXNoZWRGcm9tdAATTGphdmEvdXRpbC9FbnVtU2V0O3hwAXEAfgAtc3IAJGphdmEudXRpbC5FbnVtU2V0JFNlcmlhbGl6YXRpb25Qcm94eQUH09t2VMrRAgACTAALZWxlbWVudFR5cGV0ABFMamF2YS9sYW5nL0NsYXNzO1sACGVsZW1lbnRzdAARW0xqYXZhL2xhbmcvRW51bTt4cHZyAENzZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIuZGF0YS5kb21haW4ub2F1dGguQ2xpZW50SWQkRXN0YWJsaXNoZWRGcm9tAAAAAAAAAAASAAB4cgAOamF2YS5sYW5nLkVudW0AAAAAAAAAABIAAHhwdXIAEVtMamF2YS5sYW5nLkVudW07qI3qLTPSL5gCAAB4cAAAAAF+cQB+ADV0AAxRVUVSWV9TVFJJTkdzcQB+ABJzcQB+ABV1cQB+AAMAAAABdAJieyJ2YWx1ZSI6InNjb3BlXHUwMDNkb3BlbmlkK3VybiUzQXNlJTNBY3VyaXR5JTNBc2NvcGVzJTNBYWRtaW4lM0FhcGlcdTAwMjZzdGF0ZVx1MDAzZDdBUms4Q1dMdW9rTkdCaDdsZ3pteGp1enFqRmlSeXlzeHdFSXFkRG5KaExjdHVHY0pCNUYyR1ZiZ1RZdXlRR3NcdTAwMjZub25jZVx1MDAzZDJVSTZFNkNMYk40dFNCQ08zQXNKR2RkenFOdXR1dmtwTGJNYjUwVDIxQnZiV3NHaHVua2cwTkxSRG5BaVNIT0dcdTAwMjZjbGllbnRfaWRcdTAwM2RkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudFx1MDAyNnJlc3BvbnNlX3R5cGVcdTAwM2Rjb2RlXHUwMDI2Y29kZV9jaGFsbGVuZ2VcdTAwM2RtWXc2SzJLZUpPNEJVemFRelU3Z0YzX0laQl9aV1UteFVobUVfR3lic3h3XHUwMDI2Y29kZV9jaGFsbGVuZ2VfbWV0aG9kXHUwMDNkUzI1Nlx1MDAyNnJlZGlyZWN0X3VyaVx1MDAzZGh0dHBzJTNBJTJGJTJGbG9jYWxob3N0JTNBNjc0OSUyRmFkbWluJTJGZGFzaGJvYXJkJTJGYXNzaXN0ZWQuaHRtbFx1MDAyNmZvcl9vcmlnaW5cdTAwM2RodHRwcyUzQSUyRiUyRmxvY2FsaG9zdCUzQTY3NDkiLCJ2ZXJpZmllciI6IlJfd2NGQjM0UFBOZ0RHM1k5dVQwemJGdjV1RlRDVHlIWDIifXNxAH4AEnNxAH4AFXVxAH4AAwAAAAFzcgA9c2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLmF1dGhlbnRpY2F0aW9uLkF1dGhlbnRpY2F0aW9uUmVxdWVzdD7HPnzHCGuzAgAOWgAUX2ZvcmNlQXV0aGVudGljYXRpb25aABNfb2F1dGhBdXRob3JpemF0aW9uTAAPX2FwcGxpY2F0aW9uVXJscQB+ACpMABVfYXV0aGVudGljYXRvckZpbHRlcnN0AChMY29tL2dvb2dsZS9jb21tb24vY29sbGVjdC9JbW11dGFibGVTZXQ7TAAKX2ZyZXNobmVzc3QAEExqYXZhL2xhbmcvTG9uZztMABZfb3JpZ2luYWxSZXF1ZXN0TWV0aG9kcQB+ACpMABpfb3JpZ2luYWxSZXF1ZXN0UGFyYW1ldGVyc3QALUxjb20vZ29vZ2xlL2NvbW1vbi9jb2xsZWN0L0ltbXV0YWJsZU11bHRpbWFwO0wAHV9yZWdpc3RyYXRpb25BY3Rpb25QZXJtaXNzaW9udABGTHNlL2N1cml0eS9pZGVudGl0eXNlcnZlci9hdXRoZW50aWNhdGlvbi9SZWdpc3RyYXRpb25BY3Rpb25QZXJtaXNzaW9uO0wAEl9yZXF1ZXN0RmlsdGVyQWNyc3QAD0xqYXZhL3V0aWwvU2V0O0wAEV9yZXNwb25zZUF1ZGllbmNlcQB+ACpMAAtfcmVzdW1lUGF0aHEAfgAqTAAPX3Nzb1JlcXVpcmVtZW50dAA4THNlL2N1cml0eS9pZGVudGl0eXNlcnZlci9hdXRoZW50aWNhdGlvbi9Tc29SZXF1aXJlbWVudDtMAAZfc3RhdGVxAH4AKkwADV90ZW1wbGF0ZUFyZWFxAH4AKnhyAD5zZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIuYXV0aGVudGljYXRpb24uU2VydmljZVByb3ZpZGVyUmVxdWVzdDJzpFxVfMJmAgACRAAbX3NlcmlhbGl6YXRpb25Gb3JtYXRWZXJzaW9uTAASX3NlcnZpY2VQcm92aWRlcklkdAA+THNlL2N1cml0eS9pZGVudGl0eXNlcnZlci9wbHVnaW5zL3Byb3RvY29scy9TZXJ2aWNlUHJvdmlkZXJJZDt4cgA3c2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLmF1dGhlbnRpY2F0aW9uLkZyYW1hYmxlUmVxdWVzdIkaY3eXVW++AgADWgALX2lzRnJhbWFibGVMAA9fYWxsb3dlZE9yaWdpbnNxAH4ASEwACl9mb3JPcmlnaW5xAH4AKnhwAXNyADVjb20uZ29vZ2xlLmNvbW1vbi5jb2xsZWN0LkltbXV0YWJsZVNldCRTZXJpYWxpemVkRm9ybQAAAAAAAAAAAgABWwAIZWxlbWVudHNxAH4AFnhwdXEAfgADAAAAAXNyADJzZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIud2ViLlN0YW5kYXJkQWxsb3dlZE9yaWdpbnWDV5UT5awgAgAHSQAMX2RlZmF1bHRQb3J0WgAMX2lzMTI3XzBfMF8xWgAJX2lzT3JpZ2luSQAFX3BvcnRMAAVfaG9zdHEAfgAqTAAFX3BhdGhxAH4AKkwACV9wcm90b2NvbHEAfgAqeHAAAAG7AAEAABpddAAJbG9jYWxob3N0dAAAdAAFaHR0cHNwQAAAAAAAAABxAH4AKwABcHNxAH4ATnEAfgAjcHQAA2dldHNyAC9jb20uZ29vZ2xlLmNvbW1vbi5jb2xsZWN0LkltbXV0YWJsZUxpc3RNdWx0aW1hcAAAAAAAAAAAAwAAeHIAK2NvbS5nb29nbGUuY29tbW9uLmNvbGxlY3QuSW1tdXRhYmxlTXVsdGltYXAAAAAAAAAAAAIAAHhwdwQAAAAEdAARc2VydmljZVByb3ZpZGVySWR3BAAAAAFxAH4ALHQACWNsaWVudF9pZHcEAAAAAXEAfgAtdAAKcmVzdW1lUGF0aHcEAAAAAXQAGS9vYXV0aC92Mi9vYXV0aC1hdXRob3JpemV0AAVzdGF0ZXcEAAAAAXQAIlJfd2NGQjM0UFBOZ0RHM1k5dVQwemJGdjV1RlRDVHlIWDJ4cHNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAQ/QAAAAAAAAnNyAENzZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIuYXV0aGVudGljYXRpb24uQXV0aGVudGljYXRvcklkZW50aWZpZXJQYWly1C/g+VQ9HSkCAAFMAAVfcGFpcnQALkxvcmcvYXBhY2hlL2NvbW1vbnMvbGFuZzMvdHVwbGUvSW1tdXRhYmxlUGFpcjt4cHNyACxvcmcuYXBhY2hlLmNvbW1vbnMubGFuZzMudHVwbGUuSW1tdXRhYmxlUGFpckTDaHpt6v/RAgACTAAEbGVmdHEAfgABTAAFcmlnaHRxAH4AAXhyACNvcmcuYXBhY2hlLmNvbW1vbnMubGFuZzMudHVwbGUuUGFpckTDaHpt6v/RAgAAeHB0AAhodG1sZm9ybXQAL3VybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246aHRtbC1mb3JtOmh0bWxmb3Jtc3EAfgBjc3EAfgBmdAAIdXNlcm5hbWV0AC51cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOnVzZXJuYW1lOnVzZXJuYW1leHEAfgAscQB+AF5+cgA2c2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLmF1dGhlbnRpY2F0aW9uLlNzb1JlcXVpcmVtZW50AAAAAAAAAAASAAB4cQB+ADZ0AAROT05FcQB+AGBwc3EAfgASc3EAfgAVdXEAfgADAAAAAXQAF2RlZmF1bHQtc2ltcGxlLXByb3RvY29sc3EAfgASc3EAfgAVdXEAfgADAAAAAXNyAA5qYXZhLmxhbmcuTG9uZzuL5JDMjyPfAgABSgAFdmFsdWV4cQB+ABoAAAAAY5sGe3NxAH4AEnNxAH4AFXVxAH4AAwAAAAF0AdFzY29wZT1vcGVuaWQrdXJuJTNBc2UlM0FjdXJpdHklM0FzY29wZXMlM0FhZG1pbiUzQWFwaSZzdGF0ZT03QVJrOENXTHVva05HQmg3bGd6bXhqdXpxakZpUnl5c3h3RUlxZERuSmhMY3R1R2NKQjVGMkdWYmdUWXV5UUdzJm5vbmNlPTJVSTZFNkNMYk40dFNCQ08zQXNKR2RkenFOdXR1dmtwTGJNYjUwVDIxQnZiV3NHaHVua2cwTkxSRG5BaVNIT0cmY2xpZW50X2lkPWRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50JnJlc3BvbnNlX3R5cGU9Y29kZSZjb2RlX2NoYWxsZW5nZT1tWXc2SzJLZUpPNEJVemFRelU3Z0YzX0laQl9aV1UteFVobUVfR3lic3h3JmNvZGVfY2hhbGxlbmdlX21ldGhvZD1TMjU2JnJlZGlyZWN0X3VyaT1odHRwcyUzQSUyRiUyRmxvY2FsaG9zdCUzQTY3NDklMkZhZG1pbiUyRmRhc2hib2FyZCUyRmFzc2lzdGVkLmh0bWwmZm9yX29yaWdpbj1odHRwcyUzQSUyRiUyRmxvY2FsaG9zdCUzQTY3NDlzcQB+ABJzcQB+ABV1cQB+AAMAAAABdAAWaHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OXNxAH4AEnNxAH4AFXVxAH4AAwAAAAFzcgA8c2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLndlYi5EZWZhdWx0UXVlcnlQYXJhbWV0ZXJDb2xsZWN0aW9uPMdTMxTFwVwCAAJMAAtfcGFyYW1ldGVyc3EAfgBGTAAMX3F1ZXJ5U3RyaW5ncQB+ACp4cHNxAH4AWHcEAAAACXQABXNjb3BldwQAAAABdAAlb3BlbmlkIHVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaXQABXN0YXRldwQAAAABdABAN0FSazhDV0x1b2tOR0JoN2xnem14anV6cWpGaVJ5eXN4d0VJcWREbkpoTGN0dUdjSkI1RjJHVmJnVFl1eVFHc3QABW5vbmNldwQAAAABdABAMlVJNkU2Q0xiTjR0U0JDTzNBc0pHZGR6cU51dHV2a3BMYk1iNTBUMjFCdmJXc0dodW5rZzBOTFJEbkFpU0hPR3QACWNsaWVudF9pZHcEAAAAAXQAIGRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50dAANcmVzcG9uc2VfdHlwZXcEAAAAAXQABGNvZGV0AA5jb2RlX2NoYWxsZW5nZXcEAAAAAXQAK21ZdzZLMktlSk80QlV6YVF6VTdnRjNfSVpCX1pXVS14VWhtRV9HeWJzeHd0ABVjb2RlX2NoYWxsZW5nZV9tZXRob2R3BAAAAAF0AARTMjU2dAAMcmVkaXJlY3RfdXJpdwQAAAABdAA0aHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OS9hZG1pbi9kYXNoYm9hcmQvYXNzaXN0ZWQuaHRtbHQACmZvcl9vcmlnaW53BAAAAAF0ABZodHRwczovL2xvY2FsaG9zdDo2NzQ5eHEAfgB+c3EAfgASc3EAfgAVdXEAfgADAAAAAXQAJDA2ZTY1MjI4LTlhY2QtNDcwOS1hZmQ0LTY5ZTJiN2I1NzU0MA==	1671105962
f3e4f60a-c902-4e23-9cd9-7bd8021a17f1	rO0ABXNyADVjb20uZ29vZ2xlLmNvbW1vbi5jb2xsZWN0LkltbXV0YWJsZU1hcCRTZXJpYWxpemVkRm9ybQAAAAAAAAAAAgACTAAEa2V5c3QAEkxqYXZhL2xhbmcvT2JqZWN0O0wABnZhbHVlc3EAfgABeHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAMdAARaHRtbGZvcm0uYXR0ZW1wdHN0ABZfYXV0aG4tcmVxLmZvcmNlLWF1dGhudAAZQVVUSE5fSU5URVJNRURJQVRFX1JFU1VMVHQAHl9hdXRobi1yZXEuc2VydmljZS1wcm92aWRlci1pZHQAEVJFU1VNQUJMRV9SRVFVRVNUdAAOX19hdXRoblJlcXVlc3R0AB1wcm90b2NvbFJlcXVlc3RUcmFuc2Zvcm1lcjppZHQAIVNUQVJUX0FVVEhOX1RJTUVfQVNfRVBPQ0hfU0VDT05EU3QAG29yaWdpbmFsLWF1dGh6LXF1ZXJ5LXN0cmluZ3QAFndlYi5yZXF1ZXN0LWZvcl9vcmlnaW50ABtvcmlnaW5hbC1hdXRobi1xdWVyeS1zdHJpbmd0AA5fdHJhbnNhY3Rpb25JZHVxAH4AAwAAAAxzcgA8c2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLnNlc3Npb24uSW50ZXJuYWxTZXNzaW9uJFNlc3Npb25EYXRha/zdOk3KalwCAAFMAAZfdmFsdWV0AClMY29tL2dvb2dsZS9jb21tb24vY29sbGVjdC9JbW11dGFibGVMaXN0O3hwc3IANmNvbS5nb29nbGUuY29tbW9uLmNvbGxlY3QuSW1tdXRhYmxlTGlzdCRTZXJpYWxpemVkRm9ybQAAAAAAAAAAAgABWwAIZWxlbWVudHN0ABNbTGphdmEvbGFuZy9PYmplY3Q7eHB1cQB+AAMAAAABc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAAFzcQB+ABJzcQB+ABV1cQB+AAMAAAABc3IAEWphdmEubGFuZy5Cb29sZWFuzSBygNWc+u4CAAFaAAV2YWx1ZXhwAHNxAH4AEnNxAH4AFXVxAH4AAwAAAABzcQB+ABJzcQB+ABV1cQB+AAMAAAABc3IATXNlLmN1cml0eS5pZGVudGl0eXNlcnZlci5wbHVnaW4ucHJvdG9jb2wuc2ltcGxlYXBpLlNpbXBsZUFwaVNlcnZpY2VQcm92aWRlcklkt55a24rmGB4CAAJaABdfaXNPQXV0aFNlcnZpY2VQcm92aWRlckwACV9jbGllbnRJZHQANUxzZS9jdXJpdHkvaWRlbnRpdHlzZXJ2ZXIvZGF0YS9kb21haW4vb2F1dGgvQ2xpZW50SWQ7eHIAPHNlLmN1cml0eS5pZGVudGl0eXNlcnZlci5wbHVnaW5zLnByb3RvY29scy5TZXJ2aWNlUHJvdmlkZXJJZLCqJHYgMJVyAgACTAAKX3Byb2ZpbGVJZHQAEkxqYXZhL2xhbmcvU3RyaW5nO0wABl92YWx1ZXEAfgAqeHB0AA10b2tlbi1zZXJ2aWNldAAgZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQBc3IAM3NlLmN1cml0eS5pZGVudGl0eXNlcnZlci5kYXRhLmRvbWFpbi5vYXV0aC5DbGllbnRJZOl3K4MOWnwfAgADWgAGX3ZhbGlkTAAJX2NsaWVudElkcQB+ACpMABBfZXN0YWJsaXNoZWRGcm9tdAATTGphdmEvdXRpbC9FbnVtU2V0O3hwAXEAfgAtc3IAJGphdmEudXRpbC5FbnVtU2V0JFNlcmlhbGl6YXRpb25Qcm94eQUH09t2VMrRAgACTAALZWxlbWVudFR5cGV0ABFMamF2YS9sYW5nL0NsYXNzO1sACGVsZW1lbnRzdAARW0xqYXZhL2xhbmcvRW51bTt4cHZyAENzZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIuZGF0YS5kb21haW4ub2F1dGguQ2xpZW50SWQkRXN0YWJsaXNoZWRGcm9tAAAAAAAAAAASAAB4cgAOamF2YS5sYW5nLkVudW0AAAAAAAAAABIAAHhwdXIAEVtMamF2YS5sYW5nLkVudW07qI3qLTPSL5gCAAB4cAAAAAF+cQB+ADV0AAxRVUVSWV9TVFJJTkdzcQB+ABJzcQB+ABV1cQB+AAMAAAABdAJieyJ2YWx1ZSI6InNjb3BlXHUwMDNkb3BlbmlkK3VybiUzQXNlJTNBY3VyaXR5JTNBc2NvcGVzJTNBYWRtaW4lM0FhcGlcdTAwMjZzdGF0ZVx1MDAzZDFkNWRBTmJsMkNzQXF0N3JycFJwMlJYYlNLNHpTRUdzY09wV01aRVVwV3RFUFFBY0hINWFXU0hBYms2Z05NS2NcdTAwMjZub25jZVx1MDAzZGIyT2NjMHdDYmhST3NxQ1hSQmJTWnlQeWd6ZkVQcEpadDJFb0NEeUV0NjFFVTZYVFJuRmxHVjBucGVTdzBEQlFcdTAwMjZjbGllbnRfaWRcdTAwM2RkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudFx1MDAyNnJlc3BvbnNlX3R5cGVcdTAwM2Rjb2RlXHUwMDI2Y29kZV9jaGFsbGVuZ2VcdTAwM2Q3bjd3dW1OMFo5TC1mb1JfalhPQXNBU0hHUFNDQk9UeDhybW1UamFyUW84XHUwMDI2Y29kZV9jaGFsbGVuZ2VfbWV0aG9kXHUwMDNkUzI1Nlx1MDAyNnJlZGlyZWN0X3VyaVx1MDAzZGh0dHBzJTNBJTJGJTJGbG9jYWxob3N0JTNBNjc0OSUyRmFkbWluJTJGZGFzaGJvYXJkJTJGYXNzaXN0ZWQuaHRtbFx1MDAyNmZvcl9vcmlnaW5cdTAwM2RodHRwcyUzQSUyRiUyRmxvY2FsaG9zdCUzQTY3NDkiLCJ2ZXJpZmllciI6IlJfemNwdmhmeWpQbEJVbU5NeGpoUjFjN0ZJa2prOVlMRTAifXNxAH4AEnNxAH4AFXVxAH4AAwAAAAFzcgA9c2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLmF1dGhlbnRpY2F0aW9uLkF1dGhlbnRpY2F0aW9uUmVxdWVzdD7HPnzHCGuzAgAOWgAUX2ZvcmNlQXV0aGVudGljYXRpb25aABNfb2F1dGhBdXRob3JpemF0aW9uTAAPX2FwcGxpY2F0aW9uVXJscQB+ACpMABVfYXV0aGVudGljYXRvckZpbHRlcnN0AChMY29tL2dvb2dsZS9jb21tb24vY29sbGVjdC9JbW11dGFibGVTZXQ7TAAKX2ZyZXNobmVzc3QAEExqYXZhL2xhbmcvTG9uZztMABZfb3JpZ2luYWxSZXF1ZXN0TWV0aG9kcQB+ACpMABpfb3JpZ2luYWxSZXF1ZXN0UGFyYW1ldGVyc3QALUxjb20vZ29vZ2xlL2NvbW1vbi9jb2xsZWN0L0ltbXV0YWJsZU11bHRpbWFwO0wAHV9yZWdpc3RyYXRpb25BY3Rpb25QZXJtaXNzaW9udABGTHNlL2N1cml0eS9pZGVudGl0eXNlcnZlci9hdXRoZW50aWNhdGlvbi9SZWdpc3RyYXRpb25BY3Rpb25QZXJtaXNzaW9uO0wAEl9yZXF1ZXN0RmlsdGVyQWNyc3QAD0xqYXZhL3V0aWwvU2V0O0wAEV9yZXNwb25zZUF1ZGllbmNlcQB+ACpMAAtfcmVzdW1lUGF0aHEAfgAqTAAPX3Nzb1JlcXVpcmVtZW50dAA4THNlL2N1cml0eS9pZGVudGl0eXNlcnZlci9hdXRoZW50aWNhdGlvbi9Tc29SZXF1aXJlbWVudDtMAAZfc3RhdGVxAH4AKkwADV90ZW1wbGF0ZUFyZWFxAH4AKnhyAD5zZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIuYXV0aGVudGljYXRpb24uU2VydmljZVByb3ZpZGVyUmVxdWVzdDJzpFxVfMJmAgACRAAbX3NlcmlhbGl6YXRpb25Gb3JtYXRWZXJzaW9uTAASX3NlcnZpY2VQcm92aWRlcklkdAA+THNlL2N1cml0eS9pZGVudGl0eXNlcnZlci9wbHVnaW5zL3Byb3RvY29scy9TZXJ2aWNlUHJvdmlkZXJJZDt4cgA3c2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLmF1dGhlbnRpY2F0aW9uLkZyYW1hYmxlUmVxdWVzdIkaY3eXVW++AgADWgALX2lzRnJhbWFibGVMAA9fYWxsb3dlZE9yaWdpbnNxAH4ASEwACl9mb3JPcmlnaW5xAH4AKnhwAXNyADVjb20uZ29vZ2xlLmNvbW1vbi5jb2xsZWN0LkltbXV0YWJsZVNldCRTZXJpYWxpemVkRm9ybQAAAAAAAAAAAgABWwAIZWxlbWVudHNxAH4AFnhwdXEAfgADAAAAAXNyADJzZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIud2ViLlN0YW5kYXJkQWxsb3dlZE9yaWdpbnWDV5UT5awgAgAHSQAMX2RlZmF1bHRQb3J0WgAMX2lzMTI3XzBfMF8xWgAJX2lzT3JpZ2luSQAFX3BvcnRMAAVfaG9zdHEAfgAqTAAFX3BhdGhxAH4AKkwACV9wcm90b2NvbHEAfgAqeHAAAAG7AAEAABpddAAJbG9jYWxob3N0dAAAdAAFaHR0cHNwQAAAAAAAAABxAH4AKwABcHNxAH4ATnEAfgAjcHQAA2dldHNyAC9jb20uZ29vZ2xlLmNvbW1vbi5jb2xsZWN0LkltbXV0YWJsZUxpc3RNdWx0aW1hcAAAAAAAAAAAAwAAeHIAK2NvbS5nb29nbGUuY29tbW9uLmNvbGxlY3QuSW1tdXRhYmxlTXVsdGltYXAAAAAAAAAAAAIAAHhwdwQAAAAEdAARc2VydmljZVByb3ZpZGVySWR3BAAAAAFxAH4ALHQACWNsaWVudF9pZHcEAAAAAXEAfgAtdAAKcmVzdW1lUGF0aHcEAAAAAXQAGS9vYXV0aC92Mi9vYXV0aC1hdXRob3JpemV0AAVzdGF0ZXcEAAAAAXQAIlJfemNwdmhmeWpQbEJVbU5NeGpoUjFjN0ZJa2prOVlMRTB4cHNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAQ/QAAAAAAAAnNyAENzZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIuYXV0aGVudGljYXRpb24uQXV0aGVudGljYXRvcklkZW50aWZpZXJQYWly1C/g+VQ9HSkCAAFMAAVfcGFpcnQALkxvcmcvYXBhY2hlL2NvbW1vbnMvbGFuZzMvdHVwbGUvSW1tdXRhYmxlUGFpcjt4cHNyACxvcmcuYXBhY2hlLmNvbW1vbnMubGFuZzMudHVwbGUuSW1tdXRhYmxlUGFpckTDaHpt6v/RAgACTAAEbGVmdHEAfgABTAAFcmlnaHRxAH4AAXhyACNvcmcuYXBhY2hlLmNvbW1vbnMubGFuZzMudHVwbGUuUGFpckTDaHpt6v/RAgAAeHB0AAhodG1sZm9ybXQAL3VybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246aHRtbC1mb3JtOmh0bWxmb3Jtc3EAfgBjc3EAfgBmdAAIdXNlcm5hbWV0AC51cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOnVzZXJuYW1lOnVzZXJuYW1leHEAfgAscQB+AF5+cgA2c2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLmF1dGhlbnRpY2F0aW9uLlNzb1JlcXVpcmVtZW50AAAAAAAAAAASAAB4cQB+ADZ0AAROT05FcQB+AGBwc3EAfgASc3EAfgAVdXEAfgADAAAAAXQAF2RlZmF1bHQtc2ltcGxlLXByb3RvY29sc3EAfgASc3EAfgAVdXEAfgADAAAAAXNyAA5qYXZhLmxhbmcuTG9uZzuL5JDMjyPfAgABSgAFdmFsdWV4cQB+ABoAAAAAY5sCgnNxAH4AEnNxAH4AFXVxAH4AAwAAAAF0AdFzY29wZT1vcGVuaWQrdXJuJTNBc2UlM0FjdXJpdHklM0FzY29wZXMlM0FhZG1pbiUzQWFwaSZzdGF0ZT0xZDVkQU5ibDJDc0FxdDdycnBScDJSWGJTSzR6U0VHc2NPcFdNWkVVcFd0RVBRQWNISDVhV1NIQWJrNmdOTUtjJm5vbmNlPWIyT2NjMHdDYmhST3NxQ1hSQmJTWnlQeWd6ZkVQcEpadDJFb0NEeUV0NjFFVTZYVFJuRmxHVjBucGVTdzBEQlEmY2xpZW50X2lkPWRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50JnJlc3BvbnNlX3R5cGU9Y29kZSZjb2RlX2NoYWxsZW5nZT03bjd3dW1OMFo5TC1mb1JfalhPQXNBU0hHUFNDQk9UeDhybW1UamFyUW84JmNvZGVfY2hhbGxlbmdlX21ldGhvZD1TMjU2JnJlZGlyZWN0X3VyaT1odHRwcyUzQSUyRiUyRmxvY2FsaG9zdCUzQTY3NDklMkZhZG1pbiUyRmRhc2hib2FyZCUyRmFzc2lzdGVkLmh0bWwmZm9yX29yaWdpbj1odHRwcyUzQSUyRiUyRmxvY2FsaG9zdCUzQTY3NDlzcQB+ABJzcQB+ABV1cQB+AAMAAAABdAAWaHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OXNxAH4AEnNxAH4AFXVxAH4AAwAAAAFzcgA8c2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLndlYi5EZWZhdWx0UXVlcnlQYXJhbWV0ZXJDb2xsZWN0aW9uPMdTMxTFwVwCAAJMAAtfcGFyYW1ldGVyc3EAfgBGTAAMX3F1ZXJ5U3RyaW5ncQB+ACp4cHNxAH4AWHcEAAAACXQABXNjb3BldwQAAAABdAAlb3BlbmlkIHVybjpzZTpjdXJpdHk6c2NvcGVzOmFkbWluOmFwaXQABXN0YXRldwQAAAABdABAMWQ1ZEFOYmwyQ3NBcXQ3cnJwUnAyUlhiU0s0elNFR3NjT3BXTVpFVXBXdEVQUUFjSEg1YVdTSEFiazZnTk1LY3QABW5vbmNldwQAAAABdABAYjJPY2Mwd0NiaFJPc3FDWFJCYlNaeVB5Z3pmRVBwSlp0MkVvQ0R5RXQ2MUVVNlhUUm5GbEdWMG5wZVN3MERCUXQACWNsaWVudF9pZHcEAAAAAXQAIGRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50dAANcmVzcG9uc2VfdHlwZXcEAAAAAXQABGNvZGV0AA5jb2RlX2NoYWxsZW5nZXcEAAAAAXQAKzduN3d1bU4wWjlMLWZvUl9qWE9Bc0FTSEdQU0NCT1R4OHJtbVRqYXJRbzh0ABVjb2RlX2NoYWxsZW5nZV9tZXRob2R3BAAAAAF0AARTMjU2dAAMcmVkaXJlY3RfdXJpdwQAAAABdAA0aHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OS9hZG1pbi9kYXNoYm9hcmQvYXNzaXN0ZWQuaHRtbHQACmZvcl9vcmlnaW53BAAAAAF0ABZodHRwczovL2xvY2FsaG9zdDo2NzQ5eHEAfgB+c3EAfgASc3EAfgAVdXEAfgADAAAAAXQAJGE1ZjcwOGYzLWQwMDgtNDlkNC05YzNiLTJlMWE2NGJkM2JhOQ==	1671104946
f357c8cc-965b-4d94-a74f-61a9874d7ba7	rO0ABXNyADVjb20uZ29vZ2xlLmNvbW1vbi5jb2xsZWN0LkltbXV0YWJsZU1hcCRTZXJpYWxpemVkRm9ybQAAAAAAAAAAAgACTAAEa2V5c3QAEkxqYXZhL2xhbmcvT2JqZWN0O0wABnZhbHVlc3EAfgABeHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAHdAARaHRtbGZvcm0uYXR0ZW1wdHN0ABZfYXV0aG4tcmVxLmZvcmNlLWF1dGhudAAZQVVUSE5fSU5URVJNRURJQVRFX1JFU1VMVHQAHl9hdXRobi1yZXEuc2VydmljZS1wcm92aWRlci1pZHQADl9fYXV0aG5SZXF1ZXN0dAAhU1RBUlRfQVVUSE5fVElNRV9BU19FUE9DSF9TRUNPTkRTdAAOX3RyYW5zYWN0aW9uSWR1cQB+AAMAAAAHc3IAPHNlLmN1cml0eS5pZGVudGl0eXNlcnZlci5zZXNzaW9uLkludGVybmFsU2Vzc2lvbiRTZXNzaW9uRGF0YWv83TpNympcAgABTAAGX3ZhbHVldAApTGNvbS9nb29nbGUvY29tbW9uL2NvbGxlY3QvSW1tdXRhYmxlTGlzdDt4cHNyADZjb20uZ29vZ2xlLmNvbW1vbi5jb2xsZWN0LkltbXV0YWJsZUxpc3QkU2VyaWFsaXplZEZvcm0AAAAAAAAAAAIAAVsACGVsZW1lbnRzdAATW0xqYXZhL2xhbmcvT2JqZWN0O3hwdXEAfgADAAAAAXNyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAAAc3EAfgANc3EAfgAQdXEAfgADAAAAAXNyABFqYXZhLmxhbmcuQm9vbGVhbs0gcoDVnPruAgABWgAFdmFsdWV4cABzcQB+AA1zcQB+ABB1cQB+AAMAAAAAc3EAfgANc3EAfgAQdXEAfgADAAAAAXNyAE1zZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIucGx1Z2luLnByb3RvY29sLnNpbXBsZWFwaS5TaW1wbGVBcGlTZXJ2aWNlUHJvdmlkZXJJZLeeWtuK5hgeAgACWgAXX2lzT0F1dGhTZXJ2aWNlUHJvdmlkZXJMAAlfY2xpZW50SWR0ADVMc2UvY3VyaXR5L2lkZW50aXR5c2VydmVyL2RhdGEvZG9tYWluL29hdXRoL0NsaWVudElkO3hyADxzZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIucGx1Z2lucy5wcm90b2NvbHMuU2VydmljZVByb3ZpZGVySWSwqiR2IDCVcgIAAkwACl9wcm9maWxlSWR0ABJMamF2YS9sYW5nL1N0cmluZztMAAZfdmFsdWVxAH4AJXhwdAANdG9rZW4tc2VydmljZXQAIGRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50AXNyADNzZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIuZGF0YS5kb21haW4ub2F1dGguQ2xpZW50SWTpdyuDDlp8HwIAA1oABl92YWxpZEwACV9jbGllbnRJZHEAfgAlTAAQX2VzdGFibGlzaGVkRnJvbXQAE0xqYXZhL3V0aWwvRW51bVNldDt4cAFxAH4AKHNyACRqYXZhLnV0aWwuRW51bVNldCRTZXJpYWxpemF0aW9uUHJveHkFB9PbdlTK0QIAAkwAC2VsZW1lbnRUeXBldAARTGphdmEvbGFuZy9DbGFzcztbAAhlbGVtZW50c3QAEVtMamF2YS9sYW5nL0VudW07eHB2cgBDc2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLmRhdGEuZG9tYWluLm9hdXRoLkNsaWVudElkJEVzdGFibGlzaGVkRnJvbQAAAAAAAAAAEgAAeHIADmphdmEubGFuZy5FbnVtAAAAAAAAAAASAAB4cHVyABFbTGphdmEubGFuZy5FbnVtO6iN6i0z0i+YAgAAeHAAAAABfnEAfgAwdAAMUVVFUllfU1RSSU5Hc3EAfgANcQB+AB1zcQB+AA1zcQB+ABB1cQB+AAMAAAABc3IADmphdmEubGFuZy5Mb25nO4vkkMyPI98CAAFKAAV2YWx1ZXhxAH4AFQAAAABjmxpkc3EAfgANc3EAfgAQdXEAfgADAAAAAXQAJDUyN2YzYzExLWY1MGYtNDMzZS05MzQ2LWFlYmMyZmQ1OTQ1OQ==	1671111057
1b61d941-05e8-4751-81e1-76f41e0b793f	rO0ABXNyADVjb20uZ29vZ2xlLmNvbW1vbi5jb2xsZWN0LkltbXV0YWJsZU1hcCRTZXJpYWxpemVkRm9ybQAAAAAAAAAAAgACTAAEa2V5c3QAEkxqYXZhL2xhbmcvT2JqZWN0O0wABnZhbHVlc3EAfgABeHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAALdAAWX2F1dGhuLXJlcS5mb3JjZS1hdXRobnQAGUFVVEhOX0lOVEVSTUVESUFURV9SRVNVTFR0AB5fYXV0aG4tcmVxLnNlcnZpY2UtcHJvdmlkZXItaWR0ABFSRVNVTUFCTEVfUkVRVUVTVHQADl9fYXV0aG5SZXF1ZXN0dAAdcHJvdG9jb2xSZXF1ZXN0VHJhbnNmb3JtZXI6aWR0ACFTVEFSVF9BVVRITl9USU1FX0FTX0VQT0NIX1NFQ09ORFN0ABtvcmlnaW5hbC1hdXRoei1xdWVyeS1zdHJpbmd0ABZ3ZWIucmVxdWVzdC1mb3Jfb3JpZ2ludAAbb3JpZ2luYWwtYXV0aG4tcXVlcnktc3RyaW5ndAAOX3RyYW5zYWN0aW9uSWR1cQB+AAMAAAALc3IAPHNlLmN1cml0eS5pZGVudGl0eXNlcnZlci5zZXNzaW9uLkludGVybmFsU2Vzc2lvbiRTZXNzaW9uRGF0YWv83TpNympcAgABTAAGX3ZhbHVldAApTGNvbS9nb29nbGUvY29tbW9uL2NvbGxlY3QvSW1tdXRhYmxlTGlzdDt4cHNyADZjb20uZ29vZ2xlLmNvbW1vbi5jb2xsZWN0LkltbXV0YWJsZUxpc3QkU2VyaWFsaXplZEZvcm0AAAAAAAAAAAIAAVsACGVsZW1lbnRzdAATW0xqYXZhL2xhbmcvT2JqZWN0O3hwdXEAfgADAAAAAXNyABFqYXZhLmxhbmcuQm9vbGVhbs0gcoDVnPruAgABWgAFdmFsdWV4cABzcQB+ABFzcQB+ABR1cQB+AAMAAAAAc3EAfgARc3EAfgAUdXEAfgADAAAAAXNyAE1zZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIucGx1Z2luLnByb3RvY29sLnNpbXBsZWFwaS5TaW1wbGVBcGlTZXJ2aWNlUHJvdmlkZXJJZLeeWtuK5hgeAgACWgAXX2lzT0F1dGhTZXJ2aWNlUHJvdmlkZXJMAAlfY2xpZW50SWR0ADVMc2UvY3VyaXR5L2lkZW50aXR5c2VydmVyL2RhdGEvZG9tYWluL29hdXRoL0NsaWVudElkO3hyADxzZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIucGx1Z2lucy5wcm90b2NvbHMuU2VydmljZVByb3ZpZGVySWSwqiR2IDCVcgIAAkwACl9wcm9maWxlSWR0ABJMamF2YS9sYW5nL1N0cmluZztMAAZfdmFsdWVxAH4AI3hwdAANdG9rZW4tc2VydmljZXQAIGRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50AXNyADNzZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIuZGF0YS5kb21haW4ub2F1dGguQ2xpZW50SWTpdyuDDlp8HwIAA1oABl92YWxpZEwACV9jbGllbnRJZHEAfgAjTAAQX2VzdGFibGlzaGVkRnJvbXQAE0xqYXZhL3V0aWwvRW51bVNldDt4cAFxAH4AJnNyACRqYXZhLnV0aWwuRW51bVNldCRTZXJpYWxpemF0aW9uUHJveHkFB9PbdlTK0QIAAkwAC2VsZW1lbnRUeXBldAARTGphdmEvbGFuZy9DbGFzcztbAAhlbGVtZW50c3QAEVtMamF2YS9sYW5nL0VudW07eHB2cgBDc2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLmRhdGEuZG9tYWluLm9hdXRoLkNsaWVudElkJEVzdGFibGlzaGVkRnJvbQAAAAAAAAAAEgAAeHIADmphdmEubGFuZy5FbnVtAAAAAAAAAAASAAB4cHVyABFbTGphdmEubGFuZy5FbnVtO6iN6i0z0i+YAgAAeHAAAAABfnEAfgAudAAMUVVFUllfU1RSSU5Hc3EAfgARc3EAfgAUdXEAfgADAAAAAXQCYnsidmFsdWUiOiJzY29wZVx1MDAzZG9wZW5pZCt1cm4lM0FzZSUzQWN1cml0eSUzQXNjb3BlcyUzQWFkbWluJTNBYXBpXHUwMDI2c3RhdGVcdTAwM2RMVm1FWVp2cUZpc20yTEF1NkdyNlhjUjZmejhQSkxzQXdVaFBRdEFZd1U3cnNNZEc5WVp0dlpGWFpyU2U2cWxIXHUwMDI2bm9uY2VcdTAwM2QyWDhDQXJ0dENWRmFEZlZEZm53NEVlSzlBOW9IRnY1QVc3TXVmQk9ZcndUeUJwbWlYYTBDNUw2TUJSdGxDaEQ4XHUwMDI2Y2xpZW50X2lkXHUwMDNkZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnRcdTAwMjZyZXNwb25zZV90eXBlXHUwMDNkY29kZVx1MDAyNmNvZGVfY2hhbGxlbmdlXHUwMDNkZWpJQVZOSlktS0tPenJxeTlUN2pUb3pKNmNtYzRUWDFKdllFTm5Sc2ctTVx1MDAyNmNvZGVfY2hhbGxlbmdlX21ldGhvZFx1MDAzZFMyNTZcdTAwMjZyZWRpcmVjdF91cmlcdTAwM2RodHRwcyUzQSUyRiUyRmxvY2FsaG9zdCUzQTY3NDklMkZhZG1pbiUyRmRhc2hib2FyZCUyRmFzc2lzdGVkLmh0bWxcdTAwMjZmb3Jfb3JpZ2luXHUwMDNkaHR0cHMlM0ElMkYlMkZsb2NhbGhvc3QlM0E2NzQ5IiwidmVyaWZpZXIiOiJSX0pFd1F5N28wVjFySlh2TVhMNldjNFVqd3E5YWx6R0tsIn1zcQB+ABFzcQB+ABR1cQB+AAMAAAABc3IAPXNlLmN1cml0eS5pZGVudGl0eXNlcnZlci5hdXRoZW50aWNhdGlvbi5BdXRoZW50aWNhdGlvblJlcXVlc3Q+xz58xwhrswIADloAFF9mb3JjZUF1dGhlbnRpY2F0aW9uWgATX29hdXRoQXV0aG9yaXphdGlvbkwAD19hcHBsaWNhdGlvblVybHEAfgAjTAAVX2F1dGhlbnRpY2F0b3JGaWx0ZXJzdAAoTGNvbS9nb29nbGUvY29tbW9uL2NvbGxlY3QvSW1tdXRhYmxlU2V0O0wACl9mcmVzaG5lc3N0ABBMamF2YS9sYW5nL0xvbmc7TAAWX29yaWdpbmFsUmVxdWVzdE1ldGhvZHEAfgAjTAAaX29yaWdpbmFsUmVxdWVzdFBhcmFtZXRlcnN0AC1MY29tL2dvb2dsZS9jb21tb24vY29sbGVjdC9JbW11dGFibGVNdWx0aW1hcDtMAB1fcmVnaXN0cmF0aW9uQWN0aW9uUGVybWlzc2lvbnQARkxzZS9jdXJpdHkvaWRlbnRpdHlzZXJ2ZXIvYXV0aGVudGljYXRpb24vUmVnaXN0cmF0aW9uQWN0aW9uUGVybWlzc2lvbjtMABJfcmVxdWVzdEZpbHRlckFjcnN0AA9MamF2YS91dGlsL1NldDtMABFfcmVzcG9uc2VBdWRpZW5jZXEAfgAjTAALX3Jlc3VtZVBhdGhxAH4AI0wAD19zc29SZXF1aXJlbWVudHQAOExzZS9jdXJpdHkvaWRlbnRpdHlzZXJ2ZXIvYXV0aGVudGljYXRpb24vU3NvUmVxdWlyZW1lbnQ7TAAGX3N0YXRlcQB+ACNMAA1fdGVtcGxhdGVBcmVhcQB+ACN4cgA+c2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLmF1dGhlbnRpY2F0aW9uLlNlcnZpY2VQcm92aWRlclJlcXVlc3Qyc6RcVXzCZgIAAkQAG19zZXJpYWxpemF0aW9uRm9ybWF0VmVyc2lvbkwAEl9zZXJ2aWNlUHJvdmlkZXJJZHQAPkxzZS9jdXJpdHkvaWRlbnRpdHlzZXJ2ZXIvcGx1Z2lucy9wcm90b2NvbHMvU2VydmljZVByb3ZpZGVySWQ7eHIAN3NlLmN1cml0eS5pZGVudGl0eXNlcnZlci5hdXRoZW50aWNhdGlvbi5GcmFtYWJsZVJlcXVlc3SJGmN3l1VvvgIAA1oAC19pc0ZyYW1hYmxlTAAPX2FsbG93ZWRPcmlnaW5zcQB+AEFMAApfZm9yT3JpZ2lucQB+ACN4cAFzcgA1Y29tLmdvb2dsZS5jb21tb24uY29sbGVjdC5JbW11dGFibGVTZXQkU2VyaWFsaXplZEZvcm0AAAAAAAAAAAIAAVsACGVsZW1lbnRzcQB+ABV4cHVxAH4AAwAAAAFzcgAyc2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLndlYi5TdGFuZGFyZEFsbG93ZWRPcmlnaW51g1eVE+WsIAIAB0kADF9kZWZhdWx0UG9ydFoADF9pczEyN18wXzBfMVoACV9pc09yaWdpbkkABV9wb3J0TAAFX2hvc3RxAH4AI0wABV9wYXRocQB+ACNMAAlfcHJvdG9jb2xxAH4AI3hwAAABuwABAAAaXXQACWxvY2FsaG9zdHQAAHQABWh0dHBzcEAAAAAAAAAAcQB+ACQAAXBzcQB+AEdxAH4AHHB0AANnZXRzcgAvY29tLmdvb2dsZS5jb21tb24uY29sbGVjdC5JbW11dGFibGVMaXN0TXVsdGltYXAAAAAAAAAAAAMAAHhyACtjb20uZ29vZ2xlLmNvbW1vbi5jb2xsZWN0LkltbXV0YWJsZU11bHRpbWFwAAAAAAAAAAACAAB4cHcEAAAABHQAEXNlcnZpY2VQcm92aWRlcklkdwQAAAABcQB+ACV0AAljbGllbnRfaWR3BAAAAAFxAH4AJnQACnJlc3VtZVBhdGh3BAAAAAF0ABkvb2F1dGgvdjIvb2F1dGgtYXV0aG9yaXpldAAFc3RhdGV3BAAAAAF0ACJSX0pFd1F5N28wVjFySlh2TVhMNldjNFVqd3E5YWx6R0tseHBzcgARamF2YS51dGlsLkhhc2hTZXS6RIWVlri3NAMAAHhwdwwAAAAQP0AAAAAAAAJzcgBDc2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLmF1dGhlbnRpY2F0aW9uLkF1dGhlbnRpY2F0b3JJZGVudGlmaWVyUGFpctQv4PlUPR0pAgABTAAFX3BhaXJ0AC5Mb3JnL2FwYWNoZS9jb21tb25zL2xhbmczL3R1cGxlL0ltbXV0YWJsZVBhaXI7eHBzcgAsb3JnLmFwYWNoZS5jb21tb25zLmxhbmczLnR1cGxlLkltbXV0YWJsZVBhaXJEw2h6ber/0QIAAkwABGxlZnRxAH4AAUwABXJpZ2h0cQB+AAF4cgAjb3JnLmFwYWNoZS5jb21tb25zLmxhbmczLnR1cGxlLlBhaXJEw2h6ber/0QIAAHhwdAAIaHRtbGZvcm10AC91cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpodG1sZm9ybXNxAH4AXHNxAH4AX3QACHVzZXJuYW1ldAAudXJuOnNlOmN1cml0eTphdXRoZW50aWNhdGlvbjp1c2VybmFtZTp1c2VybmFtZXhxAH4AJXEAfgBXfnIANnNlLmN1cml0eS5pZGVudGl0eXNlcnZlci5hdXRoZW50aWNhdGlvbi5Tc29SZXF1aXJlbWVudAAAAAAAAAAAEgAAeHEAfgAvdAAETk9ORXEAfgBZcHNxAH4AEXNxAH4AFHVxAH4AAwAAAAF0ABdkZWZhdWx0LXNpbXBsZS1wcm90b2NvbHNxAH4AEXNxAH4AFHVxAH4AAwAAAAFzcgAOamF2YS5sYW5nLkxvbmc7i+SQzI8j3wIAAUoABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAGObEilzcQB+ABFzcQB+ABR1cQB+AAMAAAABdAHRc2NvcGU9b3BlbmlkK3VybiUzQXNlJTNBY3VyaXR5JTNBc2NvcGVzJTNBYWRtaW4lM0FhcGkmc3RhdGU9TFZtRVladnFGaXNtMkxBdTZHcjZYY1I2Zno4UEpMc0F3VWhQUXRBWXdVN3JzTWRHOVladHZaRlhaclNlNnFsSCZub25jZT0yWDhDQXJ0dENWRmFEZlZEZm53NEVlSzlBOW9IRnY1QVc3TXVmQk9ZcndUeUJwbWlYYTBDNUw2TUJSdGxDaEQ4JmNsaWVudF9pZD1kZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCZyZXNwb25zZV90eXBlPWNvZGUmY29kZV9jaGFsbGVuZ2U9ZWpJQVZOSlktS0tPenJxeTlUN2pUb3pKNmNtYzRUWDFKdllFTm5Sc2ctTSZjb2RlX2NoYWxsZW5nZV9tZXRob2Q9UzI1NiZyZWRpcmVjdF91cmk9aHR0cHMlM0ElMkYlMkZsb2NhbGhvc3QlM0E2NzQ5JTJGYWRtaW4lMkZkYXNoYm9hcmQlMkZhc3Npc3RlZC5odG1sJmZvcl9vcmlnaW49aHR0cHMlM0ElMkYlMkZsb2NhbGhvc3QlM0E2NzQ5c3EAfgARc3EAfgAUdXEAfgADAAAAAXQAFmh0dHBzOi8vbG9jYWxob3N0OjY3NDlzcQB+ABFzcQB+ABR1cQB+AAMAAAABc3IAPHNlLmN1cml0eS5pZGVudGl0eXNlcnZlci53ZWIuRGVmYXVsdFF1ZXJ5UGFyYW1ldGVyQ29sbGVjdGlvbjzHUzMUxcFcAgACTAALX3BhcmFtZXRlcnNxAH4AP0wADF9xdWVyeVN0cmluZ3EAfgAjeHBzcQB+AFF3BAAAAAl0AAVzY29wZXcEAAAAAXQAJW9wZW5pZCB1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGl0AAVzdGF0ZXcEAAAAAXQAQExWbUVZWnZxRmlzbTJMQXU2R3I2WGNSNmZ6OFBKTHNBd1VoUFF0QVl3VTdyc01kRzlZWnR2WkZYWnJTZTZxbEh0AAVub25jZXcEAAAAAXQAQDJYOENBcnR0Q1ZGYURmVkRmbnc0RWVLOUE5b0hGdjVBVzdNdWZCT1lyd1R5QnBtaVhhMEM1TDZNQlJ0bENoRDh0AAljbGllbnRfaWR3BAAAAAF0ACBkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudHQADXJlc3BvbnNlX3R5cGV3BAAAAAF0AARjb2RldAAOY29kZV9jaGFsbGVuZ2V3BAAAAAF0ACtlaklBVk5KWS1LS096cnF5OVQ3alRveko2Y21jNFRYMUp2WUVOblJzZy1NdAAVY29kZV9jaGFsbGVuZ2VfbWV0aG9kdwQAAAABdAAEUzI1NnQADHJlZGlyZWN0X3VyaXcEAAAAAXQANGh0dHBzOi8vbG9jYWxob3N0OjY3NDkvYWRtaW4vZGFzaGJvYXJkL2Fzc2lzdGVkLmh0bWx0AApmb3Jfb3JpZ2ludwQAAAABdAAWaHR0cHM6Ly9sb2NhbGhvc3Q6Njc0OXhxAH4AeHNxAH4AEXNxAH4AFHVxAH4AAwAAAAF0ACQ1Mjc5YWU4OC0xYjRhLTQ1MzMtOTNiYi0yNjNjZWIwZWRjODI=	1671108943
a36dad26-35ad-4cf4-90da-bee1ea14187d	rO0ABXNyADVjb20uZ29vZ2xlLmNvbW1vbi5jb2xsZWN0LkltbXV0YWJsZU1hcCRTZXJpYWxpemVkRm9ybQAAAAAAAAAAAgACTAAEa2V5c3QAEkxqYXZhL2xhbmcvT2JqZWN0O0wABnZhbHVlc3EAfgABeHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAGdAAWX2F1dGhuLXJlcS5mb3JjZS1hdXRobnQAGUFVVEhOX0lOVEVSTUVESUFURV9SRVNVTFR0AB5fYXV0aG4tcmVxLnNlcnZpY2UtcHJvdmlkZXItaWR0AA5fX2F1dGhuUmVxdWVzdHQAIVNUQVJUX0FVVEhOX1RJTUVfQVNfRVBPQ0hfU0VDT05EU3QADl90cmFuc2FjdGlvbklkdXEAfgADAAAABnNyADxzZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIuc2Vzc2lvbi5JbnRlcm5hbFNlc3Npb24kU2Vzc2lvbkRhdGFr/N06TcpqXAIAAUwABl92YWx1ZXQAKUxjb20vZ29vZ2xlL2NvbW1vbi9jb2xsZWN0L0ltbXV0YWJsZUxpc3Q7eHBzcgA2Y29tLmdvb2dsZS5jb21tb24uY29sbGVjdC5JbW11dGFibGVMaXN0JFNlcmlhbGl6ZWRGb3JtAAAAAAAAAAACAAFbAAhlbGVtZW50c3QAE1tMamF2YS9sYW5nL09iamVjdDt4cHVxAH4AAwAAAAFzcgARamF2YS5sYW5nLkJvb2xlYW7NIHKA1Zz67gIAAVoABXZhbHVleHAAc3EAfgAMc3EAfgAPdXEAfgADAAAAAHNxAH4ADHNxAH4AD3VxAH4AAwAAAAFzcgBNc2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLnBsdWdpbi5wcm90b2NvbC5zaW1wbGVhcGkuU2ltcGxlQXBpU2VydmljZVByb3ZpZGVySWS3nlrbiuYYHgIAAloAF19pc09BdXRoU2VydmljZVByb3ZpZGVyTAAJX2NsaWVudElkdAA1THNlL2N1cml0eS9pZGVudGl0eXNlcnZlci9kYXRhL2RvbWFpbi9vYXV0aC9DbGllbnRJZDt4cgA8c2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLnBsdWdpbnMucHJvdG9jb2xzLlNlcnZpY2VQcm92aWRlcklksKokdiAwlXICAAJMAApfcHJvZmlsZUlkdAASTGphdmEvbGFuZy9TdHJpbmc7TAAGX3ZhbHVlcQB+AB54cHQADXRva2VuLXNlcnZpY2V0ACBkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudAFzcgAzc2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLmRhdGEuZG9tYWluLm9hdXRoLkNsaWVudElk6Xcrgw5afB8CAANaAAZfdmFsaWRMAAlfY2xpZW50SWRxAH4AHkwAEF9lc3RhYmxpc2hlZEZyb210ABNMamF2YS91dGlsL0VudW1TZXQ7eHABcQB+ACFzcgAkamF2YS51dGlsLkVudW1TZXQkU2VyaWFsaXphdGlvblByb3h5BQfT23ZUytECAAJMAAtlbGVtZW50VHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7WwAIZWxlbWVudHN0ABFbTGphdmEvbGFuZy9FbnVtO3hwdnIAQ3NlLmN1cml0eS5pZGVudGl0eXNlcnZlci5kYXRhLmRvbWFpbi5vYXV0aC5DbGllbnRJZCRFc3RhYmxpc2hlZEZyb20AAAAAAAAAABIAAHhyAA5qYXZhLmxhbmcuRW51bQAAAAAAAAAAEgAAeHB1cgARW0xqYXZhLmxhbmcuRW51bTuojeotM9IvmAIAAHhwAAAAAX5xAH4AKXQADFFVRVJZX1NUUklOR3NxAH4ADHEAfgAWc3EAfgAMc3EAfgAPdXEAfgADAAAAAXNyAA5qYXZhLmxhbmcuTG9uZzuL5JDMjyPfAgABSgAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAAAY5sa4XNxAH4ADHNxAH4AD3VxAH4AAwAAAAF0ACQ3YjcwMjg0OS0yNjI5LTRiNGUtYmRjMy1hMzEyZjQzMmFlYTU=	1671111182
\.


--
-- Data for Name: tokens; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.tokens (token_hash, id, delegations_id, purpose, usage, format, created, expires, scope, scope_claims, status, issuer, subject, audience, not_before, claims, meta_data) FROM stdin;
qoFOvoQqrLzhJClGEiUvWLZf7qZbdpQHcP0JvZlAYzEZ7DCcjWTfv8M7t1W2ng8H+cEIrnRDeP3BTPutGJj+Dw==	\N	ff3cd915-163d-4426-834a-453c179ec039	access_token	bearer	opaque	1671101995	1671102295	openid urn:se:curity:scopes:admin:api	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	admin	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671101995	{"__mandatory__":{"delegationId":"ff3cd915-163d-4426-834a-453c179ec039","exp":1671102295,"nbf":1671101995,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"admin","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671101995,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":["admin"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"admin","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
/U/0ZDR9DPYApqZd+fwMSeMQq1drOAKrCdKd5fP5YyZMsCUoa6XTGxS2fjlrD6AVSEM0E95Jy0FK8xktQgpWCQ==	\N	a3f01399-17e3-4ff4-8fc5-718c725fa4f6	access_token	bearer	opaque	1671102309	1671102609	openid urn:se:curity:scopes:admin:api	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	admin	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671102309	{"__mandatory__":{"delegationId":"a3f01399-17e3-4ff4-8fc5-718c725fa4f6","exp":1671102609,"nbf":1671102309,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"admin","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671102309,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":["admin"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"admin","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
VKkNa1cxNeocH8hkRxe9ftP4BwGd9+/1F4I7pjg/z1htmfTp+zLi3SXJdBvKdQmB3rjQ87pQIg1TqrwUs0wVjA==	\N	672b47d8-7688-4c65-aca8-e9b092327cd8	access_token	bearer	opaque	1671102679	1671102979	openid urn:se:curity:scopes:admin:api	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	admin	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671102679	{"__mandatory__":{"delegationId":"672b47d8-7688-4c65-aca8-e9b092327cd8","exp":1671102979,"nbf":1671102679,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"admin","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671102679,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":["admin"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"admin","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
SAd57Re7sQTdMEhQvkhxWSnnQFk5tSRopZG+NYQ1drNYzIRdpgaq030JekTQWJZQp2BFbDfoXJ6vkTuDiHLUAg==	\N	a1ff7fca-f3f3-4cc3-ab17-a04f6a45859f	access_token	bearer	opaque	1671103025	1671103325	openid urn:se:curity:scopes:admin:api	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	admin	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671103025	{"__mandatory__":{"delegationId":"a1ff7fca-f3f3-4cc3-ab17-a04f6a45859f","exp":1671103325,"nbf":1671103025,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"admin","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671103025,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":["admin"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"admin","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
c4+2WR+owIKKxgCB3k6uS7fy5lQb+Jn6u5vBmrVLc+HVfoGjpY27OZUgpQylXpLRjibdOE6H3Ih13gYKMSXVYw==	\N	6f5ee3df-aad6-4493-a9c0-cc9e822087cb	access_token	bearer	opaque	1671104591	1671104891	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671104591	{"__mandatory__":{"delegationId":"6f5ee3df-aad6-4493-a9c0-cc9e822087cb","exp":1671104891,"nbf":1671104591,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671104591,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
v4GehEPAIEQ0EVlovDoxy/hWq+5B4CU5ChcFvKQT9Q8fR+4iEFdFZXDVzoHia9P5ev6j64w2WC7AIpxr9l7zmQ==	\N	bb691089-1193-4263-860f-905ccd987051	access_token	bearer	opaque	1671103311	1671103611	openid urn:se:curity:scopes:admin:api	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	admin	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671103311	{"__mandatory__":{"delegationId":"bb691089-1193-4263-860f-905ccd987051","exp":1671103611,"nbf":1671103311,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"admin","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671103311,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":["admin"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"admin","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
kzpAlpJouSjCJIJKrnkv4ug38dukIsglqRw8xoZ2kmQfk1UagwXC+CD2kLBvJ1GN7bRnBWqkhMEYMFyjN5KnJA==	\N	e64aea35-c3ba-4f02-ac54-b8beb269239e	access_token	bearer	opaque	1671103860	1671104160	openid urn:se:curity:scopes:admin:api	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	admin	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671103860	{"__mandatory__":{"delegationId":"e64aea35-c3ba-4f02-ac54-b8beb269239e","exp":1671104160,"nbf":1671103860,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"admin","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671103860,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":["admin"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"admin","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
OU31dMzjKLjQKdCDNFjkbSZesp9+tMpB6ckAkIaPUZKfWYcOIsA/shDisquwlCBVfUgi4JzoUTMJuhTN1wmNbg==	\N	91cc6b7a-7e71-44ef-8af3-7a4db5fa8cac	access_token	bearer	opaque	1671104115	1671104415	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	admin	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671104115	{"__mandatory__":{"delegationId":"91cc6b7a-7e71-44ef-8af3-7a4db5fa8cac","exp":1671104415,"nbf":1671104115,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"admin","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671104115,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":["admin"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"admin","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
NkpnWKWjjf1t7fOAape3p0LqAvfp9vu6geW1bh5qUT0RI/vDoFEGmjSRtGEt7evmxHyeXlxl/btwWjI8wY3EAQ==	\N	c38b2658-295b-4bc6-8ae2-45ee31cca11f	access_token	bearer	opaque	1671104507	1671104807	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671104507	{"__mandatory__":{"delegationId":"c38b2658-295b-4bc6-8ae2-45ee31cca11f","exp":1671104807,"nbf":1671104507,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671104507,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
W7hYjrga1wmbxQadswWjl2Ayrdq1ESLmjohKpnyZ6hcOI+vx1byawqEnBGRCaoEnLNWCbFt42wTisZk42JBZJg==	\N	f27cd88c-712f-4655-a7fe-ec4d8be70eb6	access_token	bearer	opaque	1671104609	1671104909	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671104609	{"__mandatory__":{"delegationId":"f27cd88c-712f-4655-a7fe-ec4d8be70eb6","exp":1671104909,"nbf":1671104609,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671104609,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
XhXIvcf+Wnwr/1oO39OLHQcdctvx3vi0LchL4/54bgOjcbx+/J+bK68ZFNNzd3T54O/d9dQJKDvKJf49dC6NBw==	\N	0e4592b5-709e-4ff9-852f-de726bad4f3b	access_token	bearer	opaque	1671104639	1671104939	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671104639	{"__mandatory__":{"delegationId":"0e4592b5-709e-4ff9-852f-de726bad4f3b","exp":1671104939,"nbf":1671104639,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671104639,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
Red5sFVtPNlboSB/MgMJ+wzI6xvEiC1gOG88jQHpO4NFMYwigWC7iCSqX1K5EVVJkJgQ5BphH6seXGUDtDh88A==	\N	89a4c979-bc11-4eb4-8834-e5378d12bf3f	access_token	bearer	opaque	1671104714	1671105014	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671104714	{"__mandatory__":{"delegationId":"89a4c979-bc11-4eb4-8834-e5378d12bf3f","exp":1671105014,"nbf":1671104714,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671104714,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
YY6d24Noby5aOlkt/S89FuGVKHzKYUNXK4LPjTRh1kDE3l+GX810ZXb+eymfF6n94V680tg0MLECeo7I8ZHAmA==	\N	ba633d05-f5b0-4fbf-a06f-e16b9e20ee8f	access_token	bearer	opaque	1671104779	1671105079	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671104779	{"__mandatory__":{"delegationId":"ba633d05-f5b0-4fbf-a06f-e16b9e20ee8f","exp":1671105079,"nbf":1671104779,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671104779,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
cIvLR4ANUG10WDIosrrUoAHGvfZ/mBov0nprtUKEzp05jiPJINEaeEQKIzB6hd1MgBsnLbaI0fcYnh3mnsuf1g==	\N	553b07cf-ef1c-4f63-9e27-56c546b62b24	access_token	bearer	opaque	1671104994	1671105294	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671104994	{"__mandatory__":{"delegationId":"553b07cf-ef1c-4f63-9e27-56c546b62b24","exp":1671105294,"nbf":1671104994,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671104994,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
KQEBlqN7i7pSBwU5Jkw9e9koYFWI+oitOdyynSNHqBTE2MA69jP5JWTVKSptEQ8Q0vVpL9syM2GyO76RG2rdow==	\N	a39147bd-3d95-4a7a-a2d8-b18772fe1f75	access_token	bearer	opaque	1671105014	1671105314	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671105014	{"__mandatory__":{"delegationId":"a39147bd-3d95-4a7a-a2d8-b18772fe1f75","exp":1671105314,"nbf":1671105014,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671105014,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
yw8UQTe3nzqJML9SbX/4Rsiu4w19u/AVFvcFWBxW3pqZV9EnIeQEp7lmGWo4sQWacnL7uL/mzLjOrYiQI1Q3HA==	\N	9990283c-73cf-40a2-b04e-68c061c505e6	access_token	bearer	opaque	1671105021	1671105321	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671105021	{"__mandatory__":{"delegationId":"9990283c-73cf-40a2-b04e-68c061c505e6","exp":1671105321,"nbf":1671105021,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671105021,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
mKGzqRQtUY1UF+kwoQEO+N3wlcbAPEV/W74nOZzi+UW4FuNpOlBBw4xqpM78UwTrMeMmJS9c0+LvWyYxRDJPDw==	\N	f54a818a-ab50-4c0a-98bd-b14dc0baa044	access_token	bearer	opaque	1671105090	1671105390	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671105090	{"__mandatory__":{"delegationId":"f54a818a-ab50-4c0a-98bd-b14dc0baa044","exp":1671105390,"nbf":1671105090,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671105090,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
nsNEwEkdhFrHw+zVY8ZuZMZQnGrWM0toAJIX60/yZ4GKkIkzCVj2mTjkXx6bZIM4nqzO+nZMaisWnuLrM3Lgrg==	\N	89b70705-cc69-4827-9886-5714c7862283	access_token	bearer	opaque	1671105153	1671105453	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671105153	{"__mandatory__":{"delegationId":"89b70705-cc69-4827-9886-5714c7862283","exp":1671105453,"nbf":1671105153,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671105153,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
omYqGtzT+7shxobbyah48Zt5mS/CRcR3xEYqjcxDWVIn/h0INTbgQdVRG9roP2X5gstm9tUypNXt2TxGMOJtvg==	\N	5f3823e5-6919-460c-a882-93d5b9abe00c	access_token	bearer	opaque	1671105266	1671105566	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671105266	{"__mandatory__":{"delegationId":"5f3823e5-6919-460c-a882-93d5b9abe00c","exp":1671105566,"nbf":1671105266,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671105266,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
w7VK4UKjeJy0Gn6U/RP+/6++sedAB3VKKO0B1vkpJZPn9XTlB4FWrhmWTyP30tYyVKrTxypUgt/7lzZPMgRLEA==	\N	3c11bc7a-ba28-4f3c-88f7-08eab8c5adab	access_token	bearer	opaque	1671105282	1671105582	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671105282	{"__mandatory__":{"delegationId":"3c11bc7a-ba28-4f3c-88f7-08eab8c5adab","exp":1671105582,"nbf":1671105282,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671105282,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
OOsD3CV9VXRzD8Up7o6fc7yOcrW9CQ0AjQdAolcIK08y2RG3ZvEV4R9gY9Ib3b3Tad0dzabXfmEVHLH2wGLkcg==	\N	8866d63f-c71f-4ed0-a91f-51a9d41ae4cf	access_token	bearer	opaque	1671105694	1671105994	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671105694	{"__mandatory__":{"delegationId":"8866d63f-c71f-4ed0-a91f-51a9d41ae4cf","exp":1671105994,"nbf":1671105694,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671105694,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
5j7qg2FIVvOTzBb4AsNdW250jgzSrw1UqzXcTrfDhUEzfhqAcbH66bXBG4wHh1rwbIowj6KdFrHIq/D8+BwgfQ==	\N	b197eee7-7f05-460a-a47f-036b4bcc068a	access_token	bearer	opaque	1671105850	1671106150	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671105850	{"__mandatory__":{"delegationId":"b197eee7-7f05-460a-a47f-036b4bcc068a","exp":1671106150,"nbf":1671105850,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671105850,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
ds9jbRq7QAF6E2F4+oR6gp4u22yo2FTRCOyK8/ymQ5+4FuAZXKmHCEovZysAZEKxtv+ZwSKp43K+QTP8meA3Og==	\N	9f1d4d9c-863a-4aa8-b0ae-0e994fdb3b4b	access_token	bearer	opaque	1671105897	1671106197	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671105897	{"__mandatory__":{"delegationId":"9f1d4d9c-863a-4aa8-b0ae-0e994fdb3b4b","exp":1671106197,"nbf":1671105897,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671105897,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
OVcWohFjd+t36eQSPvrzLBsCRPLGJ2nO1DLt1TpS+mSWH1rjrz+ozv4l7j7cEzj2fQfdhT4dBTXtabtXN1soGw==	\N	cbf17090-d9fd-4e7f-998f-7f321adeb06c	access_token	bearer	opaque	1671105925	1671106225	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671105925	{"__mandatory__":{"delegationId":"cbf17090-d9fd-4e7f-998f-7f321adeb06c","exp":1671106225,"nbf":1671105925,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671105925,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
ktDS1KwonQZ/1kFpx/eUvDotFk++4xCO8w585hAE+XIx4GBZvilmZ6HwUv3OW/EClsbZnCoJ1NFL/rRTIwJlEA==	\N	5cdea1f7-53a0-46da-9d9b-b6ee44d14439	access_token	bearer	opaque	1671105975	1671106275	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671105975	{"__mandatory__":{"delegationId":"5cdea1f7-53a0-46da-9d9b-b6ee44d14439","exp":1671106275,"nbf":1671105975,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671105975,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
pCVZbwmfs+0wo0z1IqIh9Z6u0oM/UJqK9vjU0G5J6JyTdey1SjO82+2kOgEtyGun0OaRXyizPmoT2xMpqe/bdA==	\N	268c5fb4-ef37-4f93-9ed6-5eeb61e41799	access_token	bearer	opaque	1671106015	1671106315	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671106015	{"__mandatory__":{"delegationId":"268c5fb4-ef37-4f93-9ed6-5eeb61e41799","exp":1671106315,"nbf":1671106015,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671106015,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
d4+TJzz8vbXYgiJEjj6i5od7csSnUhss1c/RAM5Cr4BDSoEdT8/5rXg+/GwBX+HFyA0uEXCloC069cp83j6Kfw==	\N	8914fbad-9137-4e39-90a7-c1cf7471f66d	access_token	bearer	opaque	1671106083	1671106383	accounts	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	scim-client	["scim-client"]	1671106083	{"__mandatory__":{"delegationId":"8914fbad-9137-4e39-90a7-c1cf7471f66d","exp":1671106383,"nbf":1671106083,"scope":"accounts","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"scim-client","aud":"scim-client","iat":1671106083,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":"admin"},"__metadata__":{"_requestingClientIdentifier":{"id":"scim-client"},"_requestingSubject":"scim-client","_claimMap":{"unmappedClaims":{"groups":{"scopes":["accounts"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_requestingClientAuthenticationMethod":"secret","_clientId":"scim-client"}}	\N
eORpS9jOERScFksE/8i72sEL98bOjwyClRsl0NN1bBMKIPRdemUa1gaFWJKh1Iz/CvWN3DXi96zNSs2kAFmNhw==	\N	d9a65ab6-cbbe-4c4a-84ca-e462711b2919	access_token	bearer	opaque	1671106319	1671106619	openid urn:se:curity:scopes:admin:api	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	admin	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671106319	{"__mandatory__":{"delegationId":"d9a65ab6-cbbe-4c4a-84ca-e462711b2919","exp":1671106619,"nbf":1671106319,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"admin","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671106319,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":["admin"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"admin","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
laz7ZxHmnD15fqpp2G26Ax4aWurJVIhObDg8Z1H2ukC9AsbKzsAMEdl7U7gNtf9GjTU6tL9mSys/v6I260Z3Ug==	\N	a44d96c6-5f76-49ad-a54c-c663455b75b8	access_token	bearer	opaque	1671106827	1671107127	openid urn:se:curity:scopes:admin:api	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	admin	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671106827	{"__mandatory__":{"delegationId":"a44d96c6-5f76-49ad-a54c-c663455b75b8","exp":1671107127,"nbf":1671106827,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"admin","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671106827,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":["admin"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"admin","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
BsEOO3Azz+HyWDXTtaFwHMtnJ/zyooTCxCdsGhypdIyPC6SHhWWpozTaZkeZlAT5+virE+SBazip3pwz1pywBA==	\N	b1b33041-0024-4acc-9bb3-f08b999746d8	access_token	bearer	opaque	1671106928	1671107228	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	admin	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671106928	{"__mandatory__":{"delegationId":"b1b33041-0024-4acc-9bb3-f08b999746d8","exp":1671107228,"nbf":1671106928,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"admin","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671106928,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":["admin"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"admin","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
wmFxtfXOFsVJc7x/TA/cR6sh5T9S5nQbNbuch+fkiLPJEghs+WYsGza8elFmuHWR9Z3y6GQJISgwqM5tGqExLw==	\N	e8a5ebf5-183e-4fec-b4d8-c528a37faa30	access_token	bearer	opaque	1671107013	1671107313	openid urn:se:curity:scopes:admin:api	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671107013	{"__mandatory__":{"delegationId":"e8a5ebf5-183e-4fec-b4d8-c528a37faa30","exp":1671107313,"nbf":1671107013,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671107013,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":[]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
OQnAiLXl6YnJJC0YjY0JImh0+i/yLTOcYtWpqbhBQ8V3JyEnreAC+q093VUrah7FEe8eSyWP9cyxX0NzCwRkdw==	\N	ceb53c87-d0db-4835-a3d2-b5acb3ca3666	access_token	bearer	opaque	1671107059	1671107359	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671107059	{"__mandatory__":{"delegationId":"ceb53c87-d0db-4835-a3d2-b5acb3ca3666","exp":1671107359,"nbf":1671107059,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671107059,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":[]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
Bm9JUY81gFOtVffb4TRZex/mQkjfDeje4bjYudy55aJFk9Q9egBA9zUT1zm3ZS1CTVQx321DPh4opAjdS1VbUw==	\N	ccc4f07a-ba90-4520-9d1c-0b1778ccedb2	access_token	bearer	opaque	1671109097	1671109397	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671109097	{"__mandatory__":{"delegationId":"ccc4f07a-ba90-4520-9d1c-0b1778ccedb2","exp":1671109397,"nbf":1671109097,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671109097,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":[]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
fkfhe80aKrGgNPOgwRNHWpptHQZtuTO1LqwkqpL12uxGz9SN//GShQJY0fzIby089KaucHUBxbK/ePSGG+IS8w==	\N	a12eeaea-be08-421e-b225-efcaf176d814	access_token	bearer	opaque	1671109157	1671109457	openid urn:se:curity:scopes:admin:api	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671109157	{"__mandatory__":{"delegationId":"a12eeaea-be08-421e-b225-efcaf176d814","exp":1671109457,"nbf":1671109157,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671109157,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":[]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
TPwfI1g5sP7EzkN6sX/BtVeJiGCoshKKd0NC6GkUCFqVA9aRbeuKO9JcLbUe+GEjz1IznMxqxNOKx9tEQw6HwQ==	\N	4dfa02eb-d7ba-4192-a94f-f393a5bef0c7	access_token	bearer	opaque	1671109173	1671109473	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671109173	{"__mandatory__":{"delegationId":"4dfa02eb-d7ba-4192-a94f-f393a5bef0c7","exp":1671109473,"nbf":1671109173,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671109173,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":[]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
sS2mDBJiceed9WDpy4ZqV0ohkyWpree/cwOVhsVJ0pyQiqqiw9zDk/igYmutHPgYXBfbknPlTuCbFqwqEZTNAA==	\N	43c02b5b-dd1e-4d81-a7cb-5a4febd4398b	access_token	bearer	opaque	1671109194	1671109494	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671109194	{"__mandatory__":{"delegationId":"43c02b5b-dd1e-4d81-a7cb-5a4febd4398b","exp":1671109494,"nbf":1671109194,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671109194,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":[]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
7NN67l0R1/CM2OPJVWjn2ln5fcHSTR/C1DYearJgL7psW4VjfyDPFjK+re27xBdALpmk/1pCk8P2AzJV86lqaQ==	\N	a43f4b24-4d65-4ac8-9397-69157aac1617	access_token	bearer	opaque	1671109227	1671109527	openid urn:se:curity:scopes:admin:api	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671109227	{"__mandatory__":{"delegationId":"a43f4b24-4d65-4ac8-9397-69157aac1617","exp":1671109527,"nbf":1671109227,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671109227,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":[]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
mrUQo06iRG2xtH+Jej5+BLUPI3GLUdWvbMAHdrAvY/gOw7bfEA5xkfXoTZMrtJd+HTAIyo07nKOcdFhf6I4nKg==	\N	ac5585b3-5e79-490c-adcf-0df17ac56248	access_token	bearer	opaque	1671109352	1671109652	openid urn:se:curity:scopes:admin:api	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671109352	{"__mandatory__":{"delegationId":"ac5585b3-5e79-490c-adcf-0df17ac56248","exp":1671109652,"nbf":1671109352,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671109352,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"urn:se:curity:claims:admin:groups":[]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"urn:se:curity:claims:admin:groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
\.


--
-- Name: accounts accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (account_id);


--
-- Name: audit audit_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.audit
    ADD CONSTRAINT audit_pkey PRIMARY KEY (id);


--
-- Name: buckets buckets_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.buckets
    ADD CONSTRAINT buckets_pkey PRIMARY KEY (subject, purpose);


--
-- Name: delegations delegations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.delegations
    ADD CONSTRAINT delegations_pkey PRIMARY KEY (id);


--
-- Name: devices devices_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (id);


--
-- Name: dynamically_registered_clients dynamically_registered_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dynamically_registered_clients
    ADD CONSTRAINT dynamically_registered_clients_pkey PRIMARY KEY (client_id);


--
-- Name: linked_accounts linked_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.linked_accounts
    ADD CONSTRAINT linked_accounts_pkey PRIMARY KEY (linked_account_id, linked_account_domain_name);


--
-- Name: nonces nonces_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.nonces
    ADD CONSTRAINT nonces_pkey PRIMARY KEY (token);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: tokens tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.tokens
    ADD CONSTRAINT tokens_pkey PRIMARY KEY (token_hash);


--
-- Name: idx_accounts_attributes_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_accounts_attributes_name ON public.accounts USING gin (((attributes -> 'name'::text)));


--
-- Name: idx_accounts_email; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX idx_accounts_email ON public.accounts USING btree (email);


--
-- Name: idx_accounts_phone; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX idx_accounts_phone ON public.accounts USING btree (phone);


--
-- Name: idx_accounts_username; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX idx_accounts_username ON public.accounts USING btree (username);


--
-- Name: idx_buckets_attributes; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_buckets_attributes ON public.buckets USING gin (attributes);


--
-- Name: idx_delegations_authorization_code_hash; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_delegations_authorization_code_hash ON public.delegations USING btree (authorization_code_hash);


--
-- Name: idx_delegations_client_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_delegations_client_id ON public.delegations USING btree (client_id);


--
-- Name: idx_delegations_expires; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_delegations_expires ON public.delegations USING btree (expires);


--
-- Name: idx_delegations_owner; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_delegations_owner ON public.delegations USING btree (owner);


--
-- Name: idx_delegations_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_delegations_status ON public.delegations USING btree (status);


--
-- Name: idx_devices_account_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_devices_account_id ON public.devices USING btree (account_id);


--
-- Name: idx_devices_device_id_account_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX idx_devices_device_id_account_id ON public.devices USING btree (device_id, account_id);


--
-- Name: idx_drc_attributes; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_drc_attributes ON public.dynamically_registered_clients USING gin (attributes);


--
-- Name: idx_drc_instance_of_client; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_drc_instance_of_client ON public.dynamically_registered_clients USING btree (instance_of_client);


--
-- Name: idx_linked_accounts_accounts_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_linked_accounts_accounts_id ON public.linked_accounts USING btree (account_id);


--
-- Name: idx_sessions_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_sessions_id ON public.sessions USING btree (id);


--
-- Name: idx_sessions_id_expires; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_sessions_id_expires ON public.sessions USING btree (id, expires);


--
-- Name: idx_tokens_expires; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_tokens_expires ON public.tokens USING btree (expires);


--
-- Name: idx_tokens_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_tokens_id ON public.tokens USING btree (id);


--
-- Name: idx_tokens_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_tokens_status ON public.tokens USING btree (status);


--
-- PostgreSQL database dump complete
--

