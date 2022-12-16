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
f2d15608-7d48-11ed-9a61-0242ac1b0002	bob	\N	bob@customer.com	\N	{"name": {"givenName": "bob", "familyName": ""}, "title": "", "emails": [{"type": "", "value": "bob@customer.com", "primary": false}], "groups": [], "locale": "", "nickName": "", "addresses": [], "displayName": "", "entitlements": [], "phoneNumbers": []}	1	1671198778	1671198778
0636ffae-7d49-11ed-9a61-0242ac1b0002	alice	\N	alice@customer.com	\N	{"name": {"givenName": "alice", "familyName": ""}, "title": "", "emails": [{"type": "", "value": "alice@customer.com", "primary": false}], "groups": [], "locale": "", "nickName": "", "addresses": [], "displayName": "", "entitlements": [], "phoneNumbers": []}	1	1671198810	1671198810
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
5d3702ed-7c8a-47a2-a28a-c9a4dbe25572	johndoe	1671198349	1671198649	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":{"groups":"devops"}},"delegation-version":"4.1"}	{"subject":{"subject":"johndoe","username":"johndoe","role":"devops"},"context":{"iat":1671198349338,"auth_time":1671198349,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"RifRwn0sFSXYQNoY"}}}	v1lwuePGggyWIqksUGgVKT6g8nd4BhGOqRGePPweyn11mUimQXKi18roLeyHG87uTFPMBh4othhX/tKNCRXQdw==
5bb11577-be8e-49fe-adc3-71384ad70ad9	johndoe	1671198432	1671198732	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":["devops"]},"delegation-version":"4.1"}	{"subject":{"subject":"johndoe","username":"johndoe","role":"devops"},"context":{"iat":1671198432483,"auth_time":1671198432,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"p2176AZjupc0xm6z"}}}	Vfr7Ug7F3xgceJU/VJvg0S23PtS3Cznq0t78Z2sB40RTROP2+arcMj5vFdqQyXZYAdnHEsmOLteYrTd2FCMN5g==
e4faa90d-9c1c-4694-994a-f3848ea3c4ff	johndoe	1671198464	1671198764	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":["devops"]},"delegation-version":"4.1"}	{"subject":{"subject":"johndoe","username":"johndoe","role":"devops"},"context":{"iat":1671198432483,"auth_time":1671198432,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"p2176AZjupc0xm6z"}}}	b5JVrRpIfL+OjpegMhFvtVEG+JtS5W8lc761MtIompZeHeOxLAnw89dtxg/sOuoIUjrTRjAQaxw+cR8cRJDxxA==
1af89a19-55b9-42c7-8d9e-3199c61aeeaf	johndoe	1671198467	1671198767	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":["devops"]},"delegation-version":"4.1"}	{"subject":{"subject":"johndoe","username":"johndoe","role":"devops"},"context":{"iat":1671198467115,"auth_time":1671198467,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"NPUyci04lhDHgljk"}}}	acZdJd7uKzWzAGUg8JmwNPwN+wejVKtMerbQWo8bbHmbBEuVTpjBHlardGSxOz4jv6tOuFIcBkxSQQaX6zcXJg==
413ef586-0573-4096-aa32-759460191e22	janedoe	1671198475	1671198775	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":["developer"]},"delegation-version":"4.1"}	{"subject":{"subject":"janedoe","username":"janedoe","role":"developer"},"context":{"iat":1671198474897,"auth_time":1671198474,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"GgZEaR99K4RQrhYT"}}}	BEfX4wHOMpmZtTvpprqiaVhbAsqzsgE9vQuTIkzazxu85m8CE2dEQ12ooaU1DxZ47aPPHnqIDwa8uvDonrPH/w==
fc07f544-5c8f-4c43-a591-82e657e52cb5	janedoe	1671198482	1671198782	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":["developer"]},"delegation-version":"4.1"}	{"subject":{"subject":"janedoe","username":"janedoe","role":"developer"},"context":{"iat":1671198481897,"auth_time":1671198481,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"SnpDiaBamwuluzfS"}}}	T2jCwQeHsZna9RlRog/DieM9I6cPYdKShFGwnvLeprWm55LdwxfwmIYps1RuNJCIO8fV7XN1QPsGOSspOWL+FQ==
c63c9bed-3c96-483b-bfdb-a90af6b6c3ca	johndoe	1671198494	1671198794	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":["devops"]},"delegation-version":"4.1"}	{"subject":{"subject":"johndoe","username":"johndoe","role":"devops"},"context":{"iat":1671198494270,"auth_time":1671198494,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"YYUQW5G4vGdQB0Zy"}}}	RqX0Vq1KbtjqHw7jtyQk9LzlpgTg2FQ7HDKA/kVy4a3dBFd1LlQW+Z0vz/4V6YvRCiR5S82IzJhigk2Uma330Q==
7ee93507-4bdf-46db-b6d0-d1630f27e306	janedoe	1671198532	1671198832	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":["developers"]},"delegation-version":"4.1"}	{"subject":{"subject":"janedoe","username":"janedoe","role":"developers"},"context":{"iat":1671198532863,"auth_time":1671198532,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"hYlRL6YEUwlcL5ni"}}}	9B057/uAJvYDravzygKK9GdhDqhmVUq6J8cSC9GlckbPw+Rq7yQS9lMpm+b6f1VySlM4jH1oCxhhrI2Bi3gL9g==
4e84e35f-6c25-41c8-8302-f401a657d130	janedoe	1671198577	1671198877	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":["developers"]},"delegation-version":"4.1"}	{"subject":{"subject":"janedoe","username":"janedoe","role":"developers"},"context":{"iat":1671198577303,"auth_time":1671198577,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"EF2curqoJNizyTHk"}}}	SaK0kGGlwCwUvP9hTeTbbAqaOKkCOFbScLENd9OMNCGMh7cKYvSu4cygzHz+qjeFiBqMSSXixZIB6OyBPN3b6g==
0fb5381c-e54d-44b4-b9e8-3591446fd66a	johndoe	1671198599	1671198899	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":["devops"]},"delegation-version":"4.1"}	{"subject":{"subject":"johndoe","username":"johndoe","role":"devops"},"context":{"iat":1671198599701,"auth_time":1671198599,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"FnQcbXn4pvmFVcU3"}}}	b6WkvUCn7blbg9NSlWKUcdeWzmfKeEHQhKrjHdBWwMQQ6HipZ/yOHUw4IDHYxbsd4CC2/t8zCCrJdD2xpo65pg==
665eba53-2d8c-4460-a3f7-a68a6bb6b7cf	johndoe	1671198688	1671198988	openid urn:se:curity:scopes:admin:api	[{"scope":"urn:se:curity:scopes:admin:api","claim":"groups","required":false}]	devops_dashboard_restconf_client	https://localhost:6749/admin/dashboard/assisted.html	issued	{"resolvedClaimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"customClaimValues":{"groups":["devops"]},"delegation-version":"4.1"}	{"subject":{"subject":"johndoe","username":"johndoe","role":"devops"},"context":{"iat":1671198688196,"auth_time":1671198688,"acr":"urn:se:curity:authentication:username:username","authenticationSessionData":{"serviceProviderProfileId":"token-service","serviceProviderId":"devops_dashboard_restconf_client","sid":"6SiK8vqMKNB4c8P5"}}}	zTD+/2zyAiuXAmV4INOurLNKuljCxYeaWHOOxT8yXHiCFbawmC7n+RHunQ9PIEaMYOrpH66LrJBnsZqak6lHRA==
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
WP3VqLwZofuJLbfVOPzRWdRpAkzcv4nN	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg2NDksImNyZWF0ZWQiOjE2NzExOTgzNDksInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTk4MzQ5MzM4LCJhdXRoX3RpbWUiOjE2NzExOTgzNDksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiUmlmUnduMHNGU1hZUU5vWSJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjA2MjY4Nzk2LTllNTctNDZmMy1hYWE3LWNjNGI3YTg0ZWZlZCIsInN1YmplY3QiOnsic3ViamVjdCI6ImpvaG5kb2UiLCJ1c2VybmFtZSI6ImpvaG5kb2UiLCJyb2xlIjoiZGV2b3BzIn19fQ==	1671198349	300	1671198349	used
q0kQGcao38Qd1CEo3UA3niLHdlB9fGBL	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTgzNzksImNyZWF0ZWQiOjE2NzExOTgzNDksInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7InN1YmplY3QiOiJqb2huZG9lIiwidXNlcm5hbWUiOiJqb2huZG9lIiwicm9sZSI6ImRldm9wcyJ9LCJjb250ZXh0Ijp7ImlhdCI6MTY3MTE5ODM0OTMzOCwiYXV0aF90aW1lIjoxNjcxMTk4MzQ5LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOnVzZXJuYW1lOnVzZXJuYW1lIiwiYXV0aGVudGljYXRpb25TZXNzaW9uRGF0YSI6eyJzZXJ2aWNlUHJvdmlkZXJQcm9maWxlSWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2VydmljZVByb3ZpZGVySWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInNpZCI6IlJpZlJ3bjBzRlNYWVFOb1kifX19LCJjb2RlQ2hhbGxlbmdlTWV0aG9kIjoiUzI1NiIsIm5vbmNlIjoiaE1udE9Ta2V6eWxVUjZkQjk0bnB5TEloOUQ5RGhVQ204ZmtWR0ZIVUJ5QTVwVG53Yk81TWRmRWZReVdOSHhqYiIsInNpZCI6IlJpZlJ3bjBzRlNYWVFOb1kiLCJzY29wZSI6Im9wZW5pZCB1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiLCJjbGFpbXMiOnsidW5tYXBwZWRDbGFpbXMiOnsiZ3JvdXBzIjp7InNjb3BlcyI6WyJ1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiXX0sImlzcyI6eyJyZXF1aXJlZCI6dHJ1ZX0sInN1YiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1ZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImV4cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImlhdCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1dGhfdGltZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5vbmNlIjp7InJlcXVpcmVkIjp0cnVlfSwiYWNyIjp7InJlcXVpcmVkIjp0cnVlfSwiYW1yIjp7InJlcXVpcmVkIjp0cnVlfSwiYXpwIjp7InJlcXVpcmVkIjp0cnVlfSwibmJmIjp7InJlcXVpcmVkIjp0cnVlfSwiY2xpZW50X2lkIjp7InJlcXVpcmVkIjp0cnVlfSwiZGVsZWdhdGlvbl9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sInB1cnBvc2UiOnsicmVxdWlyZWQiOnRydWV9LCJzY29wZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImp0aSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNpZCI6eyJyZXF1aXJlZCI6dHJ1ZX19fSwiY29kZUNoYWxsZW5nZSI6IjVORnF1dlVZUDJwMHpxN0VLVjlOYXpmSEp4NUFPaEYyS3NvSnhmR0RjTHciLCJzdGF0ZSI6InZlRGozYlYwYVdaTmo2WDNtdTVMMWZ0aDFHMFNhbjFoWnhEVjh0c1pDYUVrSDVVMWpqM1JaanhvOHZjU2pLVGYifX0=	1671198349	30	1671198349	used
xMAzRITZeX2KkwojOiVwktVwwvqIBPb9	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg3MzIsImNyZWF0ZWQiOjE2NzExOTg0MzIsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTk4NDMyNDgzLCJhdXRoX3RpbWUiOjE2NzExOTg0MzIsImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoicDIxNzZBWmp1cGMweG02eiJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjA2MjY4Nzk2LTllNTctNDZmMy1hYWE3LWNjNGI3YTg0ZWZlZCIsInN1YmplY3QiOnsic3ViamVjdCI6ImpvaG5kb2UiLCJ1c2VybmFtZSI6ImpvaG5kb2UiLCJyb2xlIjoiZGV2b3BzIn19fQ==	1671198432	300	1671198432	used
pCSdy0fDCbVqcFU7D531nJnCbJNuSeVw	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg0NjIsImNyZWF0ZWQiOjE2NzExOTg0MzIsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7InN1YmplY3QiOiJqb2huZG9lIiwidXNlcm5hbWUiOiJqb2huZG9lIiwicm9sZSI6ImRldm9wcyJ9LCJjb250ZXh0Ijp7ImlhdCI6MTY3MTE5ODQzMjQ4MywiYXV0aF90aW1lIjoxNjcxMTk4NDMyLCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOnVzZXJuYW1lOnVzZXJuYW1lIiwiYXV0aGVudGljYXRpb25TZXNzaW9uRGF0YSI6eyJzZXJ2aWNlUHJvdmlkZXJQcm9maWxlSWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2VydmljZVByb3ZpZGVySWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInNpZCI6InAyMTc2QVpqdXBjMHhtNnoifX19LCJjb2RlQ2hhbGxlbmdlTWV0aG9kIjoiUzI1NiIsIm5vbmNlIjoiaDF2TVdCTVRPdTBSOGE0Q04yTjBlMFF5aXNCTDJ6T2luTXVYZW0yTHY0NW1UR1BVZkVTY0N6V0JxbGxGeXJsQyIsInNpZCI6InAyMTc2QVpqdXBjMHhtNnoiLCJzY29wZSI6Im9wZW5pZCB1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiLCJjbGFpbXMiOnsidW5tYXBwZWRDbGFpbXMiOnsiZ3JvdXBzIjp7InNjb3BlcyI6WyJ1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiXX0sImlzcyI6eyJyZXF1aXJlZCI6dHJ1ZX0sInN1YiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1ZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImV4cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImlhdCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1dGhfdGltZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5vbmNlIjp7InJlcXVpcmVkIjp0cnVlfSwiYWNyIjp7InJlcXVpcmVkIjp0cnVlfSwiYW1yIjp7InJlcXVpcmVkIjp0cnVlfSwiYXpwIjp7InJlcXVpcmVkIjp0cnVlfSwibmJmIjp7InJlcXVpcmVkIjp0cnVlfSwiY2xpZW50X2lkIjp7InJlcXVpcmVkIjp0cnVlfSwiZGVsZWdhdGlvbl9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sInB1cnBvc2UiOnsicmVxdWlyZWQiOnRydWV9LCJzY29wZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImp0aSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNpZCI6eyJyZXF1aXJlZCI6dHJ1ZX19fSwiY29kZUNoYWxsZW5nZSI6IkNjWjBEdERUb3RWdXZOUFdpQ2tsc0NNMTFuNHBKV3N4X25HU2RkNk1WcHciLCJzdGF0ZSI6IkhvSUdqTFpuNDI5RGxhWXZ1VjdwWFRhMFRiTEFOVDExU3F5ZVRHT2VDaW5VdklBek1UU3JDSXFXdTZnVjBWMUwifX0=	1671198432	30	1671198432	used
lXH3KFqQ60XbgPwD15jmqAblSYomcLyw	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg3NjQsImNyZWF0ZWQiOjE2NzExOTg0NjQsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTk4NDMyNDgzLCJhdXRoX3RpbWUiOjE2NzExOTg0MzIsImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoicDIxNzZBWmp1cGMweG02eiJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjA2MjY4Nzk2LTllNTctNDZmMy1hYWE3LWNjNGI3YTg0ZWZlZCIsInN1YmplY3QiOnsic3ViamVjdCI6ImpvaG5kb2UiLCJ1c2VybmFtZSI6ImpvaG5kb2UiLCJyb2xlIjoiZGV2b3BzIn19fQ==	1671198464	300	1671198464	used
BYa2aXinuhfTQsWPaCqeYCu6nd37EhZk	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg0OTQsImNyZWF0ZWQiOjE2NzExOTg0NjQsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7InN1YmplY3QiOiJqb2huZG9lIiwidXNlcm5hbWUiOiJqb2huZG9lIiwicm9sZSI6ImRldm9wcyJ9LCJjb250ZXh0Ijp7ImlhdCI6MTY3MTE5ODQzMjQ4MywiYXV0aF90aW1lIjoxNjcxMTk4NDMyLCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOnVzZXJuYW1lOnVzZXJuYW1lIiwiYXV0aGVudGljYXRpb25TZXNzaW9uRGF0YSI6eyJzZXJ2aWNlUHJvdmlkZXJQcm9maWxlSWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2VydmljZVByb3ZpZGVySWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInNpZCI6InAyMTc2QVpqdXBjMHhtNnoifX19LCJjb2RlQ2hhbGxlbmdlTWV0aG9kIjoiUzI1NiIsIm5vbmNlIjoiRGNIY0VDS2VrZEI5WE1UM3pPV3FDczc3eEw2V2hJdjlTeDFJN3J2bUNyQ1pQcmh1TXl3RlJXU2xGeFRtTHBKeCIsInNpZCI6InAyMTc2QVpqdXBjMHhtNnoiLCJzY29wZSI6Im9wZW5pZCB1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiLCJjbGFpbXMiOnsidW5tYXBwZWRDbGFpbXMiOnsiZ3JvdXBzIjp7InNjb3BlcyI6WyJ1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiXX0sImlzcyI6eyJyZXF1aXJlZCI6dHJ1ZX0sInN1YiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1ZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImV4cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImlhdCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1dGhfdGltZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5vbmNlIjp7InJlcXVpcmVkIjp0cnVlfSwiYWNyIjp7InJlcXVpcmVkIjp0cnVlfSwiYW1yIjp7InJlcXVpcmVkIjp0cnVlfSwiYXpwIjp7InJlcXVpcmVkIjp0cnVlfSwibmJmIjp7InJlcXVpcmVkIjp0cnVlfSwiY2xpZW50X2lkIjp7InJlcXVpcmVkIjp0cnVlfSwiZGVsZWdhdGlvbl9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sInB1cnBvc2UiOnsicmVxdWlyZWQiOnRydWV9LCJzY29wZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImp0aSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNpZCI6eyJyZXF1aXJlZCI6dHJ1ZX19fSwiY29kZUNoYWxsZW5nZSI6InRGMHNEM3ZlNEtBdVIzeGtKUFRiNGkweUc4Wjg5bmQ3STBaWUUyZjFzWE0iLCJzdGF0ZSI6ImdsWHpreVFxa2xKakpyWXFSd25QWVRGUGcwdnpoam9ESXdGZ3B0azR4a0VXdkNSS2NDaFNBc1VQSERSNjlXRnQifX0=	1671198464	30	1671198464	used
Te216uAotQDcEMPguJU9Qg4XypptIyuS	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg3NjcsImNyZWF0ZWQiOjE2NzExOTg0NjcsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTk4NDY3MTE1LCJhdXRoX3RpbWUiOjE2NzExOTg0NjcsImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiTlBVeWNpMDRsaERIZ2xqayJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjA2MjY4Nzk2LTllNTctNDZmMy1hYWE3LWNjNGI3YTg0ZWZlZCIsInN1YmplY3QiOnsic3ViamVjdCI6ImpvaG5kb2UiLCJ1c2VybmFtZSI6ImpvaG5kb2UiLCJyb2xlIjoiZGV2b3BzIn19fQ==	1671198467	300	1671198467	used
xNzRm5DBUVMzpdQ79IfSnzdKCKkjsnnh	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg0OTcsImNyZWF0ZWQiOjE2NzExOTg0NjcsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7InN1YmplY3QiOiJqb2huZG9lIiwidXNlcm5hbWUiOiJqb2huZG9lIiwicm9sZSI6ImRldm9wcyJ9LCJjb250ZXh0Ijp7ImlhdCI6MTY3MTE5ODQ2NzExNSwiYXV0aF90aW1lIjoxNjcxMTk4NDY3LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOnVzZXJuYW1lOnVzZXJuYW1lIiwiYXV0aGVudGljYXRpb25TZXNzaW9uRGF0YSI6eyJzZXJ2aWNlUHJvdmlkZXJQcm9maWxlSWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2VydmljZVByb3ZpZGVySWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInNpZCI6Ik5QVXljaTA0bGhESGdsamsifX19LCJjb2RlQ2hhbGxlbmdlTWV0aG9kIjoiUzI1NiIsIm5vbmNlIjoiaHl5cWFBd0piYzFuY3BlMFpBc2Y1OVdwV3R0c295ZHQ1QWNZQWVCeHJLZTlTd2JHS1dIck5UeWdtNzlmbjJQQiIsInNpZCI6Ik5QVXljaTA0bGhESGdsamsiLCJzY29wZSI6Im9wZW5pZCB1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiLCJjbGFpbXMiOnsidW5tYXBwZWRDbGFpbXMiOnsiZ3JvdXBzIjp7InNjb3BlcyI6WyJ1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiXX0sImlzcyI6eyJyZXF1aXJlZCI6dHJ1ZX0sInN1YiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1ZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImV4cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImlhdCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1dGhfdGltZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5vbmNlIjp7InJlcXVpcmVkIjp0cnVlfSwiYWNyIjp7InJlcXVpcmVkIjp0cnVlfSwiYW1yIjp7InJlcXVpcmVkIjp0cnVlfSwiYXpwIjp7InJlcXVpcmVkIjp0cnVlfSwibmJmIjp7InJlcXVpcmVkIjp0cnVlfSwiY2xpZW50X2lkIjp7InJlcXVpcmVkIjp0cnVlfSwiZGVsZWdhdGlvbl9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sInB1cnBvc2UiOnsicmVxdWlyZWQiOnRydWV9LCJzY29wZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImp0aSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNpZCI6eyJyZXF1aXJlZCI6dHJ1ZX19fSwiY29kZUNoYWxsZW5nZSI6InktdE9qYndmUHJsbHE0WTBfUDlfWE5nZFF5U3N1eVJkRU92MTc5dG5ldzQiLCJzdGF0ZSI6Im5MWkFLWGMzTFEyNHZHSk83MnFlTk1QajUzUkJmWlQzRWJQTHgyQ1Z4aUVHQ0ljZWdodFhzUksyWkFLbkp1VmgifX0=	1671198467	30	1671198467	used
nIdK5efyh0LLO4nRuHknNPCNELOtxz27	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg3NzQsImNyZWF0ZWQiOjE2NzExOTg0NzQsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTk4NDc0ODk3LCJhdXRoX3RpbWUiOjE2NzExOTg0NzQsImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiR2daRWFSOTlLNFJRcmhZVCJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjA2MjY4Nzk2LTllNTctNDZmMy1hYWE3LWNjNGI3YTg0ZWZlZCIsInN1YmplY3QiOnsic3ViamVjdCI6ImphbmVkb2UiLCJ1c2VybmFtZSI6ImphbmVkb2UiLCJyb2xlIjoiZGV2ZWxvcGVyIn19fQ==	1671198474	300	1671198474	used
SPVQbctO1HTjnzReoTz6Y2q6MWNJcJX9	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg1MDQsImNyZWF0ZWQiOjE2NzExOTg0NzQsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqYW5lZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7InN1YmplY3QiOiJqYW5lZG9lIiwidXNlcm5hbWUiOiJqYW5lZG9lIiwicm9sZSI6ImRldmVsb3BlciJ9LCJjb250ZXh0Ijp7ImlhdCI6MTY3MTE5ODQ3NDg5NywiYXV0aF90aW1lIjoxNjcxMTk4NDc0LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOnVzZXJuYW1lOnVzZXJuYW1lIiwiYXV0aGVudGljYXRpb25TZXNzaW9uRGF0YSI6eyJzZXJ2aWNlUHJvdmlkZXJQcm9maWxlSWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2VydmljZVByb3ZpZGVySWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInNpZCI6IkdnWkVhUjk5SzRSUXJoWVQifX19LCJjb2RlQ2hhbGxlbmdlTWV0aG9kIjoiUzI1NiIsIm5vbmNlIjoiaThBNTk2NmhoTFY4enh2aUdhUEZHNDJtaHR1SE05eFplaHJ1VFRqTlJKdDBIWjk5bnJOU1VudkdQMERnUUdzdCIsInNpZCI6IkdnWkVhUjk5SzRSUXJoWVQiLCJzY29wZSI6Im9wZW5pZCB1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiLCJjbGFpbXMiOnsidW5tYXBwZWRDbGFpbXMiOnsiZ3JvdXBzIjp7InNjb3BlcyI6WyJ1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiXX0sImlzcyI6eyJyZXF1aXJlZCI6dHJ1ZX0sInN1YiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1ZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImV4cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImlhdCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1dGhfdGltZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5vbmNlIjp7InJlcXVpcmVkIjp0cnVlfSwiYWNyIjp7InJlcXVpcmVkIjp0cnVlfSwiYW1yIjp7InJlcXVpcmVkIjp0cnVlfSwiYXpwIjp7InJlcXVpcmVkIjp0cnVlfSwibmJmIjp7InJlcXVpcmVkIjp0cnVlfSwiY2xpZW50X2lkIjp7InJlcXVpcmVkIjp0cnVlfSwiZGVsZWdhdGlvbl9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sInB1cnBvc2UiOnsicmVxdWlyZWQiOnRydWV9LCJzY29wZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImp0aSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNpZCI6eyJyZXF1aXJlZCI6dHJ1ZX19fSwiY29kZUNoYWxsZW5nZSI6IjdkbktmckU1QV82eXZ1cVBMa214MmNQRHNON2s1M3lRQXZXVHRaQUkxZ00iLCJzdGF0ZSI6ImhlNVVnVU9TdFF2bmk3ZGRYd2xUMHpFTm10OTdkNHdDWlZ2YW1aa0JCR1BmTkg5cDRvRllIcG82ZDNSeVI2enMifX0=	1671198474	30	1671198475	used
pOoFsPUL7OWTIZVRSDrT4QwLzwgwIBUR	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg3ODEsImNyZWF0ZWQiOjE2NzExOTg0ODEsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTk4NDgxODk3LCJhdXRoX3RpbWUiOjE2NzExOTg0ODEsImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiU25wRGlhQmFtd3VsdXpmUyJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjA2MjY4Nzk2LTllNTctNDZmMy1hYWE3LWNjNGI3YTg0ZWZlZCIsInN1YmplY3QiOnsic3ViamVjdCI6ImphbmVkb2UiLCJ1c2VybmFtZSI6ImphbmVkb2UiLCJyb2xlIjoiZGV2ZWxvcGVyIn19fQ==	1671198481	300	1671198481	used
qspNVQzdLTNFYKnRCguHOxl96Uj8kavR	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg1MTEsImNyZWF0ZWQiOjE2NzExOTg0ODEsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqYW5lZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7InN1YmplY3QiOiJqYW5lZG9lIiwidXNlcm5hbWUiOiJqYW5lZG9lIiwicm9sZSI6ImRldmVsb3BlciJ9LCJjb250ZXh0Ijp7ImlhdCI6MTY3MTE5ODQ4MTg5NywiYXV0aF90aW1lIjoxNjcxMTk4NDgxLCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOnVzZXJuYW1lOnVzZXJuYW1lIiwiYXV0aGVudGljYXRpb25TZXNzaW9uRGF0YSI6eyJzZXJ2aWNlUHJvdmlkZXJQcm9maWxlSWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2VydmljZVByb3ZpZGVySWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInNpZCI6IlNucERpYUJhbXd1bHV6ZlMifX19LCJjb2RlQ2hhbGxlbmdlTWV0aG9kIjoiUzI1NiIsIm5vbmNlIjoiSmtXUmNIZTRwUll3VjZmcVFFUml6UXh0ZGdrVk1SanR2NTVUSlF2dmN4Ynl5ZjdLZUUyQVY3cVFCazNwbzlWRCIsInNpZCI6IlNucERpYUJhbXd1bHV6ZlMiLCJzY29wZSI6Im9wZW5pZCB1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiLCJjbGFpbXMiOnsidW5tYXBwZWRDbGFpbXMiOnsiZ3JvdXBzIjp7InNjb3BlcyI6WyJ1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiXX0sImlzcyI6eyJyZXF1aXJlZCI6dHJ1ZX0sInN1YiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1ZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImV4cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImlhdCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1dGhfdGltZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5vbmNlIjp7InJlcXVpcmVkIjp0cnVlfSwiYWNyIjp7InJlcXVpcmVkIjp0cnVlfSwiYW1yIjp7InJlcXVpcmVkIjp0cnVlfSwiYXpwIjp7InJlcXVpcmVkIjp0cnVlfSwibmJmIjp7InJlcXVpcmVkIjp0cnVlfSwiY2xpZW50X2lkIjp7InJlcXVpcmVkIjp0cnVlfSwiZGVsZWdhdGlvbl9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sInB1cnBvc2UiOnsicmVxdWlyZWQiOnRydWV9LCJzY29wZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImp0aSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNpZCI6eyJyZXF1aXJlZCI6dHJ1ZX19fSwiY29kZUNoYWxsZW5nZSI6IkpVODNaNTNRUlJVQk1qeFhmaF9kMXB4eDUwRmhnaVR0STJVYzkydC01TUkiLCJzdGF0ZSI6Imw3VDFwRFc0Z1ZCRkdBcEVyVUJEMXJqTExJNDJIUG1WUkN4T0dBWlRJamc2aTBQNGlxbDF1bUFYRWpwTFlKcGIifX0=	1671198481	30	1671198482	used
numBfxBS7WfpwCPrybnrTJP6Plkww2rv	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg3OTQsImNyZWF0ZWQiOjE2NzExOTg0OTQsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTk4NDk0MjcwLCJhdXRoX3RpbWUiOjE2NzExOTg0OTQsImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiWVlVUVc1RzR2R2RRQjBaeSJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjA2MjY4Nzk2LTllNTctNDZmMy1hYWE3LWNjNGI3YTg0ZWZlZCIsInN1YmplY3QiOnsic3ViamVjdCI6ImpvaG5kb2UiLCJ1c2VybmFtZSI6ImpvaG5kb2UiLCJyb2xlIjoiZGV2b3BzIn19fQ==	1671198494	300	1671198494	used
zhOndsesXNa7sT70XYGJSlX4P4f0yTRG	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg1MjQsImNyZWF0ZWQiOjE2NzExOTg0OTQsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7InN1YmplY3QiOiJqb2huZG9lIiwidXNlcm5hbWUiOiJqb2huZG9lIiwicm9sZSI6ImRldm9wcyJ9LCJjb250ZXh0Ijp7ImlhdCI6MTY3MTE5ODQ5NDI3MCwiYXV0aF90aW1lIjoxNjcxMTk4NDk0LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOnVzZXJuYW1lOnVzZXJuYW1lIiwiYXV0aGVudGljYXRpb25TZXNzaW9uRGF0YSI6eyJzZXJ2aWNlUHJvdmlkZXJQcm9maWxlSWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2VydmljZVByb3ZpZGVySWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInNpZCI6IllZVVFXNUc0dkdkUUIwWnkifX19LCJjb2RlQ2hhbGxlbmdlTWV0aG9kIjoiUzI1NiIsIm5vbmNlIjoiR3IzSThIampuMEhlaXFWc3JLZ0JnREhZc0loamVkY2ZRMk9wSDIzZW9mcHNFY0tsTHVBeEtocjdBR040TjFCZiIsInNpZCI6IllZVVFXNUc0dkdkUUIwWnkiLCJzY29wZSI6Im9wZW5pZCB1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiLCJjbGFpbXMiOnsidW5tYXBwZWRDbGFpbXMiOnsiZ3JvdXBzIjp7InNjb3BlcyI6WyJ1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiXX0sImlzcyI6eyJyZXF1aXJlZCI6dHJ1ZX0sInN1YiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1ZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImV4cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImlhdCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1dGhfdGltZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5vbmNlIjp7InJlcXVpcmVkIjp0cnVlfSwiYWNyIjp7InJlcXVpcmVkIjp0cnVlfSwiYW1yIjp7InJlcXVpcmVkIjp0cnVlfSwiYXpwIjp7InJlcXVpcmVkIjp0cnVlfSwibmJmIjp7InJlcXVpcmVkIjp0cnVlfSwiY2xpZW50X2lkIjp7InJlcXVpcmVkIjp0cnVlfSwiZGVsZWdhdGlvbl9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sInB1cnBvc2UiOnsicmVxdWlyZWQiOnRydWV9LCJzY29wZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImp0aSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNpZCI6eyJyZXF1aXJlZCI6dHJ1ZX19fSwiY29kZUNoYWxsZW5nZSI6IlBSUHlTUi04aG5SSHdYX2c4akxxQTJYNy0ySS15MHpQVkZ2UUZRNHBkcGMiLCJzdGF0ZSI6IjVOYkh1WERsazNpWE5wdjF1dFVCTVdFdFA4M1hYU3ZHVHUzQkJ6ejU3eUxLWmN6M1NBOU1NWUl0d0xDWEVUWk0ifX0=	1671198494	30	1671198494	used
TL5Zi4WYIDPE1lpCEC4f8nkapoplijgn	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg4MzIsImNyZWF0ZWQiOjE2NzExOTg1MzIsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTk4NTMyODYzLCJhdXRoX3RpbWUiOjE2NzExOTg1MzIsImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiaFlsUkw2WUVVd2xjTDVuaSJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjA2MjY4Nzk2LTllNTctNDZmMy1hYWE3LWNjNGI3YTg0ZWZlZCIsInN1YmplY3QiOnsic3ViamVjdCI6ImphbmVkb2UiLCJ1c2VybmFtZSI6ImphbmVkb2UiLCJyb2xlIjoiZGV2ZWxvcGVycyJ9fX0=	1671198532	300	1671198532	used
nTVQNcvvvaH3EqO9mjUllPbBjzNuYDzq	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg1NjIsImNyZWF0ZWQiOjE2NzExOTg1MzIsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqYW5lZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7InN1YmplY3QiOiJqYW5lZG9lIiwidXNlcm5hbWUiOiJqYW5lZG9lIiwicm9sZSI6ImRldmVsb3BlcnMifSwiY29udGV4dCI6eyJpYXQiOjE2NzExOTg1MzI4NjMsImF1dGhfdGltZSI6MTY3MTE5ODUzMiwiYWNyIjoidXJuOnNlOmN1cml0eTphdXRoZW50aWNhdGlvbjp1c2VybmFtZTp1c2VybmFtZSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJoWWxSTDZZRVV3bGNMNW5pIn19fSwiY29kZUNoYWxsZW5nZU1ldGhvZCI6IlMyNTYiLCJub25jZSI6IjhmSXZBSDlnMnQ5R3hlVzQ1c2x1Tk9TZjhzR3lDS0NGcjVVTWFJZmI3UmJVUWNXTGx6RGkxa2xCNmx4TDlwZk4iLCJzaWQiOiJoWWxSTDZZRVV3bGNMNW5pIiwic2NvcGUiOiJvcGVuaWQgdXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIiwiY2xhaW1zIjp7InVubWFwcGVkQ2xhaW1zIjp7Imdyb3VwcyI6eyJzY29wZXMiOlsidXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIl19LCJpc3MiOnsicmVxdWlyZWQiOnRydWV9LCJzdWIiOnsicmVxdWlyZWQiOnRydWV9LCJhdWQiOnsicmVxdWlyZWQiOnRydWV9LCJleHAiOnsicmVxdWlyZWQiOnRydWV9LCJpYXQiOnsicmVxdWlyZWQiOnRydWV9LCJhdXRoX3RpbWUiOnsicmVxdWlyZWQiOnRydWV9LCJub25jZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFjciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFtciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF6cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5iZiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImNsaWVudF9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImRlbGVnYXRpb25faWQiOnsicmVxdWlyZWQiOnRydWV9LCJwdXJwb3NlIjp7InJlcXVpcmVkIjp0cnVlfSwic2NvcGUiOnsicmVxdWlyZWQiOnRydWV9LCJqdGkiOnsicmVxdWlyZWQiOnRydWV9LCJzaWQiOnsicmVxdWlyZWQiOnRydWV9fX0sImNvZGVDaGFsbGVuZ2UiOiJsUkpqZXJITExLUDUzS3R4eG5ObUFOYkFpNDRzNzZ1ZHdiN0JpdkVpOFJZIiwic3RhdGUiOiI1NElRM1hON243ckFaQWF3Y3Y5SlhNMFpqQmFkQnBlVGhuTmtJaUl1QnptVHN5MDRBVlFlVmVHdU5YZUczTVNJIn19	1671198532	30	1671198532	used
AIM8VzDDsXcUPfsEAbtckkWDmLENtMgb	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg4NzcsImNyZWF0ZWQiOjE2NzExOTg1NzcsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTk4NTc3MzAzLCJhdXRoX3RpbWUiOjE2NzExOTg1NzcsImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiRUYyY3VycW9KTml6eVRIayJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjA2MjY4Nzk2LTllNTctNDZmMy1hYWE3LWNjNGI3YTg0ZWZlZCIsInN1YmplY3QiOnsic3ViamVjdCI6ImphbmVkb2UiLCJ1c2VybmFtZSI6ImphbmVkb2UiLCJyb2xlIjoiZGV2ZWxvcGVycyJ9fX0=	1671198577	300	1671198577	used
jHD2m3nMY8Ip4fa7yrsxOOhNATnE3I02	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg2MDcsImNyZWF0ZWQiOjE2NzExOTg1NzcsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqYW5lZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7InN1YmplY3QiOiJqYW5lZG9lIiwidXNlcm5hbWUiOiJqYW5lZG9lIiwicm9sZSI6ImRldmVsb3BlcnMifSwiY29udGV4dCI6eyJpYXQiOjE2NzExOTg1NzczMDMsImF1dGhfdGltZSI6MTY3MTE5ODU3NywiYWNyIjoidXJuOnNlOmN1cml0eTphdXRoZW50aWNhdGlvbjp1c2VybmFtZTp1c2VybmFtZSIsImF1dGhlbnRpY2F0aW9uU2Vzc2lvbkRhdGEiOnsic2VydmljZVByb3ZpZGVyUHJvZmlsZUlkIjoidG9rZW4tc2VydmljZSIsInNlcnZpY2VQcm92aWRlcklkIjoiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiLCJzaWQiOiJFRjJjdXJxb0pOaXp5VEhrIn19fSwiY29kZUNoYWxsZW5nZU1ldGhvZCI6IlMyNTYiLCJub25jZSI6Inl3SHJCY3RqdzdXOFhFSHJ4cExMSVFnSHBvcEp5ZzV1VkRJakZZUUZmSUVFdlR6MkF2WWF5N1d6MEhEUnY0ZTIiLCJzaWQiOiJFRjJjdXJxb0pOaXp5VEhrIiwic2NvcGUiOiJvcGVuaWQgdXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIiwiY2xhaW1zIjp7InVubWFwcGVkQ2xhaW1zIjp7Imdyb3VwcyI6eyJzY29wZXMiOlsidXJuOnNlOmN1cml0eTpzY29wZXM6YWRtaW46YXBpIl19LCJpc3MiOnsicmVxdWlyZWQiOnRydWV9LCJzdWIiOnsicmVxdWlyZWQiOnRydWV9LCJhdWQiOnsicmVxdWlyZWQiOnRydWV9LCJleHAiOnsicmVxdWlyZWQiOnRydWV9LCJpYXQiOnsicmVxdWlyZWQiOnRydWV9LCJhdXRoX3RpbWUiOnsicmVxdWlyZWQiOnRydWV9LCJub25jZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFjciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImFtciI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF6cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5iZiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImNsaWVudF9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImRlbGVnYXRpb25faWQiOnsicmVxdWlyZWQiOnRydWV9LCJwdXJwb3NlIjp7InJlcXVpcmVkIjp0cnVlfSwic2NvcGUiOnsicmVxdWlyZWQiOnRydWV9LCJqdGkiOnsicmVxdWlyZWQiOnRydWV9LCJzaWQiOnsicmVxdWlyZWQiOnRydWV9fX0sImNvZGVDaGFsbGVuZ2UiOiJLNmZjS0JEbi1BbTBVWDBDQWU0ZkRhY3BERzY2U2FBejhrZmtId0owVHRJIiwic3RhdGUiOiI1ajVkRnFDc3BQdFZzQ0hBT0tFWENXSzczTlVQcTVGQ21ZM2IxZ1hJMHB5dWcwaGdnZGlYVHdQQk9xckl4RlFRIn19	1671198577	30	1671198577	used
OLb0CrqK7lfIvitpxWJEHa1C1AkoNlEN	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg4OTksImNyZWF0ZWQiOjE2NzExOTg1OTksInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTk4NTk5NzAxLCJhdXRoX3RpbWUiOjE2NzExOTg1OTksImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiRm5RY2JYbjRwdm1GVmNVMyJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjA2MjY4Nzk2LTllNTctNDZmMy1hYWE3LWNjNGI3YTg0ZWZlZCIsInN1YmplY3QiOnsic3ViamVjdCI6ImpvaG5kb2UiLCJ1c2VybmFtZSI6ImpvaG5kb2UiLCJyb2xlIjoiZGV2b3BzIn19fQ==	1671198599	300	1671198599	used
4nBxFo2kOWNpMj7rbuwzh2yMcFVh8mL0	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg2MjksImNyZWF0ZWQiOjE2NzExOTg1OTksInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7InN1YmplY3QiOiJqb2huZG9lIiwidXNlcm5hbWUiOiJqb2huZG9lIiwicm9sZSI6ImRldm9wcyJ9LCJjb250ZXh0Ijp7ImlhdCI6MTY3MTE5ODU5OTcwMSwiYXV0aF90aW1lIjoxNjcxMTk4NTk5LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOnVzZXJuYW1lOnVzZXJuYW1lIiwiYXV0aGVudGljYXRpb25TZXNzaW9uRGF0YSI6eyJzZXJ2aWNlUHJvdmlkZXJQcm9maWxlSWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2VydmljZVByb3ZpZGVySWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInNpZCI6IkZuUWNiWG40cHZtRlZjVTMifX19LCJjb2RlQ2hhbGxlbmdlTWV0aG9kIjoiUzI1NiIsIm5vbmNlIjoiRmtybE1acEppUTFGRlcxMGxWdjlFSEJqTjRnbm15WU1DQ3p2V1N1YmJYOEFRUnIxYzVHSUJPWDN6MUVsOTJJdCIsInNpZCI6IkZuUWNiWG40cHZtRlZjVTMiLCJzY29wZSI6Im9wZW5pZCB1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiLCJjbGFpbXMiOnsidW5tYXBwZWRDbGFpbXMiOnsiZ3JvdXBzIjp7InNjb3BlcyI6WyJ1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiXX0sImlzcyI6eyJyZXF1aXJlZCI6dHJ1ZX0sInN1YiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1ZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImV4cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImlhdCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1dGhfdGltZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5vbmNlIjp7InJlcXVpcmVkIjp0cnVlfSwiYWNyIjp7InJlcXVpcmVkIjp0cnVlfSwiYW1yIjp7InJlcXVpcmVkIjp0cnVlfSwiYXpwIjp7InJlcXVpcmVkIjp0cnVlfSwibmJmIjp7InJlcXVpcmVkIjp0cnVlfSwiY2xpZW50X2lkIjp7InJlcXVpcmVkIjp0cnVlfSwiZGVsZWdhdGlvbl9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sInB1cnBvc2UiOnsicmVxdWlyZWQiOnRydWV9LCJzY29wZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImp0aSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNpZCI6eyJyZXF1aXJlZCI6dHJ1ZX19fSwiY29kZUNoYWxsZW5nZSI6IllfZVdCbGF3al9SQXFLbjhVMnBqMEQ1VDhvLWpxeE93UGtnMURtUzUzWkUiLCJzdGF0ZSI6IlZodVg4aHVzSzlIcmx3U0N5Y0llZkQzdWlMOWlsQ0pBZkl5eDZDSEVycHBiaWxCVHQwUzdHdXZWRkpjZVZCTVUifX0=	1671198599	30	1671198599	used
aoKhLwzelnh9axaGnB1MEkk5tnQSEPwN	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg5ODgsImNyZWF0ZWQiOjE2NzExOTg2ODgsInB1cnBvc2UiOiJsb2dpbl90b2tlbiJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsiaXNzIjoiYXV0aGVudGljYXRpb24tc2VydmljZSIsImNvbnRleHQiOnsiaWF0IjoxNjcxMTk4Njg4MTk2LCJhdXRoX3RpbWUiOjE2NzExOTg2ODgsImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246dXNlcm5hbWU6dXNlcm5hbWUiLCJhdXRoZW50aWNhdGlvblNlc3Npb25EYXRhIjp7InNlcnZpY2VQcm92aWRlclByb2ZpbGVJZCI6InRva2VuLXNlcnZpY2UiLCJzZXJ2aWNlUHJvdmlkZXJJZCI6ImRldm9wc19kYXNoYm9hcmRfcmVzdGNvbmZfY2xpZW50Iiwic2lkIjoiNlNpSzh2cU1LTkI0YzhQNSJ9fSwiYXVkIjoidG9rZW4tc2VydmljZSIsInNlc3Npb25JZCI6IjA2MjY4Nzk2LTllNTctNDZmMy1hYWE3LWNjNGI3YTg0ZWZlZCIsInN1YmplY3QiOnsic3ViamVjdCI6ImpvaG5kb2UiLCJ1c2VybmFtZSI6ImpvaG5kb2UiLCJyb2xlIjoiZGV2b3BzIn19fQ==	1671198688	300	1671198688	used
DPl1obBOpymjuex7t5SW9FPzaYcZ00kT	eyJfX21hbmRhdG9yeV9fIjp7ImV4cGlyZXMiOjE2NzExOTg3MTgsImNyZWF0ZWQiOjE2NzExOTg2ODgsInB1cnBvc2UiOiJub25jZSJ9LCJfX3Rva2VuX2NsYXNzX25hbWVfXyI6InNlLmN1cml0eS5pZGVudGl0eXNlcnZlci50b2tlbnMuZGF0YS5Ob25jZURhdGEiLCJfX29wdGlvbmFsX18iOnsib3duZXIiOiJqb2huZG9lIiwicmVkaXJlY3RVcmkiOiJodHRwczovL2xvY2FsaG9zdDo2NzQ5L2FkbWluL2Rhc2hib2FyZC9hc3Npc3RlZC5odG1sIiwiYXVkaWVuY2UiOlsidXJuOnNlOmN1cml0eTphdWRpZW5jZXM6YWRtaW46YXBpIiwiZGV2b3BzX2Rhc2hib2FyZF9yZXN0Y29uZl9jbGllbnQiXSwiY2xpZW50SWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInJlZGlyZWN0VXJpUHJvdmlkZWQiOnRydWUsImF1dGhlbnRpY2F0aW9uQXR0cmlidXRlcyI6eyJzdWJqZWN0Ijp7InN1YmplY3QiOiJqb2huZG9lIiwidXNlcm5hbWUiOiJqb2huZG9lIiwicm9sZSI6ImRldm9wcyJ9LCJjb250ZXh0Ijp7ImlhdCI6MTY3MTE5ODY4ODE5NiwiYXV0aF90aW1lIjoxNjcxMTk4Njg4LCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOnVzZXJuYW1lOnVzZXJuYW1lIiwiYXV0aGVudGljYXRpb25TZXNzaW9uRGF0YSI6eyJzZXJ2aWNlUHJvdmlkZXJQcm9maWxlSWQiOiJ0b2tlbi1zZXJ2aWNlIiwic2VydmljZVByb3ZpZGVySWQiOiJkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudCIsInNpZCI6IjZTaUs4dnFNS05CNGM4UDUifX19LCJjb2RlQ2hhbGxlbmdlTWV0aG9kIjoiUzI1NiIsIm5vbmNlIjoiOHlNcXhRSklBNEtpZ2tVYzJUSkFNVVY0aWthVkQzcHlJTEFodXdlSWwxWGZIdlZuSTNXcDhjWndicTRhUG5DSSIsInNpZCI6IjZTaUs4dnFNS05CNGM4UDUiLCJzY29wZSI6Im9wZW5pZCB1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiLCJjbGFpbXMiOnsidW5tYXBwZWRDbGFpbXMiOnsiZ3JvdXBzIjp7InNjb3BlcyI6WyJ1cm46c2U6Y3VyaXR5OnNjb3BlczphZG1pbjphcGkiXX0sImlzcyI6eyJyZXF1aXJlZCI6dHJ1ZX0sInN1YiI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1ZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImV4cCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImlhdCI6eyJyZXF1aXJlZCI6dHJ1ZX0sImF1dGhfdGltZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sIm5vbmNlIjp7InJlcXVpcmVkIjp0cnVlfSwiYWNyIjp7InJlcXVpcmVkIjp0cnVlfSwiYW1yIjp7InJlcXVpcmVkIjp0cnVlfSwiYXpwIjp7InJlcXVpcmVkIjp0cnVlfSwibmJmIjp7InJlcXVpcmVkIjp0cnVlfSwiY2xpZW50X2lkIjp7InJlcXVpcmVkIjp0cnVlfSwiZGVsZWdhdGlvbl9pZCI6eyJyZXF1aXJlZCI6dHJ1ZX0sInB1cnBvc2UiOnsicmVxdWlyZWQiOnRydWV9LCJzY29wZSI6eyJyZXF1aXJlZCI6dHJ1ZX0sImp0aSI6eyJyZXF1aXJlZCI6dHJ1ZX0sInNpZCI6eyJyZXF1aXJlZCI6dHJ1ZX19fSwiY29kZUNoYWxsZW5nZSI6Imh1cGZVQ0F3SWNVcjhYMmRxeXhUSmpNbVBCVGtzV2NnRFJRLWtsSkNrcUkiLCJzdGF0ZSI6IkJJY2IzaUZ5RnJZa25HR0tPNkRFeE5lcDFlZUVKbUhqWWY2SEZiaXVldmkxNHZOMVJ3RUVpSEowZDQwbjZvQ3kifX0=	1671198688	30	1671198688	used
\.


--
-- Data for Name: sessions; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.sessions (id, session_data, expires) FROM stdin;
06268796-9e57-46f3-aaa7-cc4b7a84efed	rO0ABXNyADVjb20uZ29vZ2xlLmNvbW1vbi5jb2xsZWN0LkltbXV0YWJsZU1hcCRTZXJpYWxpemVkRm9ybQAAAAAAAAAAAgACTAAEa2V5c3QAEkxqYXZhL2xhbmcvT2JqZWN0O0wABnZhbHVlc3EAfgABeHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAGdAAWX2F1dGhuLXJlcS5mb3JjZS1hdXRobnQAGUFVVEhOX0lOVEVSTUVESUFURV9SRVNVTFR0AB5fYXV0aG4tcmVxLnNlcnZpY2UtcHJvdmlkZXItaWR0AA5fX2F1dGhuUmVxdWVzdHQAIVNUQVJUX0FVVEhOX1RJTUVfQVNfRVBPQ0hfU0VDT05EU3QADl90cmFuc2FjdGlvbklkdXEAfgADAAAABnNyADxzZS5jdXJpdHkuaWRlbnRpdHlzZXJ2ZXIuc2Vzc2lvbi5JbnRlcm5hbFNlc3Npb24kU2Vzc2lvbkRhdGFr/N06TcpqXAIAAUwABl92YWx1ZXQAKUxjb20vZ29vZ2xlL2NvbW1vbi9jb2xsZWN0L0ltbXV0YWJsZUxpc3Q7eHBzcgA2Y29tLmdvb2dsZS5jb21tb24uY29sbGVjdC5JbW11dGFibGVMaXN0JFNlcmlhbGl6ZWRGb3JtAAAAAAAAAAACAAFbAAhlbGVtZW50c3QAE1tMamF2YS9sYW5nL09iamVjdDt4cHVxAH4AAwAAAAFzcgARamF2YS5sYW5nLkJvb2xlYW7NIHKA1Zz67gIAAVoABXZhbHVleHAAc3EAfgAMc3EAfgAPdXEAfgADAAAAAHNxAH4ADHNxAH4AD3VxAH4AAwAAAAFzcgBNc2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLnBsdWdpbi5wcm90b2NvbC5zaW1wbGVhcGkuU2ltcGxlQXBpU2VydmljZVByb3ZpZGVySWS3nlrbiuYYHgIAAloAF19pc09BdXRoU2VydmljZVByb3ZpZGVyTAAJX2NsaWVudElkdAA1THNlL2N1cml0eS9pZGVudGl0eXNlcnZlci9kYXRhL2RvbWFpbi9vYXV0aC9DbGllbnRJZDt4cgA8c2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLnBsdWdpbnMucHJvdG9jb2xzLlNlcnZpY2VQcm92aWRlcklksKokdiAwlXICAAJMAApfcHJvZmlsZUlkdAASTGphdmEvbGFuZy9TdHJpbmc7TAAGX3ZhbHVlcQB+AB54cHQADXRva2VuLXNlcnZpY2V0ACBkZXZvcHNfZGFzaGJvYXJkX3Jlc3Rjb25mX2NsaWVudAFzcgAzc2UuY3VyaXR5LmlkZW50aXR5c2VydmVyLmRhdGEuZG9tYWluLm9hdXRoLkNsaWVudElk6Xcrgw5afB8CAANaAAZfdmFsaWRMAAlfY2xpZW50SWRxAH4AHkwAEF9lc3RhYmxpc2hlZEZyb210ABNMamF2YS91dGlsL0VudW1TZXQ7eHABcQB+ACFzcgAkamF2YS51dGlsLkVudW1TZXQkU2VyaWFsaXphdGlvblByb3h5BQfT23ZUytECAAJMAAtlbGVtZW50VHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7WwAIZWxlbWVudHN0ABFbTGphdmEvbGFuZy9FbnVtO3hwdnIAQ3NlLmN1cml0eS5pZGVudGl0eXNlcnZlci5kYXRhLmRvbWFpbi5vYXV0aC5DbGllbnRJZCRFc3RhYmxpc2hlZEZyb20AAAAAAAAAABIAAHhyAA5qYXZhLmxhbmcuRW51bQAAAAAAAAAAEgAAeHB1cgARW0xqYXZhLmxhbmcuRW51bTuojeotM9IvmAIAAHhwAAAAAX5xAH4AKXQADFFVRVJZX1NUUklOR3NxAH4ADHEAfgAWc3EAfgAMc3EAfgAPdXEAfgADAAAAAXNyAA5qYXZhLmxhbmcuTG9uZzuL5JDMjyPfAgABSgAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAAAY5x33nNxAH4ADHNxAH4AD3VxAH4AAwAAAAF0ACRiZmEyNTUwNy1iNTJhLTQzYTAtYjRjNS1lMDdhMjFkNWQxYzg=	1671200518
\.


--
-- Data for Name: tokens; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.tokens (token_hash, id, delegations_id, purpose, usage, format, created, expires, scope, scope_claims, status, issuer, subject, audience, not_before, claims, meta_data) FROM stdin;
KbEQXfVlWEvYMyh2tEb86Xo1l3uBgqXypU3aluuZH/O+ZJ5+dUzXa+7BNpTRniiMhWqZLL16/pmCUZPtO5UKbw==	\N	5d3702ed-7c8a-47a2-a28a-c9a4dbe25572	access_token	bearer	opaque	1671198349	1671198649	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671198349	{"__mandatory__":{"delegationId":"5d3702ed-7c8a-47a2-a28a-c9a4dbe25572","exp":1671198649,"nbf":1671198349,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671198349,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":{"groups":"devops"}},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
LZxP7w8GSjMi+qskZOfPIt+BEWh+32JakPbSIIwwEzN5STKdUduJOt83+4VvnKomo2L9qGelLlMWZg2kllbKJw==	\N	5bb11577-be8e-49fe-adc3-71384ad70ad9	access_token	bearer	opaque	1671198432	1671198732	openid urn:se:curity:scopes:admin:api	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671198432	{"__mandatory__":{"delegationId":"5bb11577-be8e-49fe-adc3-71384ad70ad9","exp":1671198732,"nbf":1671198432,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671198432,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":["devops"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
fLsAM0OhdhdIRfz4/nPU5+37ES+f6qFC9lxc0ZegovLxEiZx/qHKjv2pLHvV+gpNKQVxULWySYs4mcWRS0SSUg==	\N	e4faa90d-9c1c-4694-994a-f3848ea3c4ff	access_token	bearer	opaque	1671198464	1671198764	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671198464	{"__mandatory__":{"delegationId":"e4faa90d-9c1c-4694-994a-f3848ea3c4ff","exp":1671198764,"nbf":1671198464,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671198464,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":["devops"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
+7hRPi2SGbSnOZsc/JfLm/aLrrvnWrnxkPahWTntDFLSy+C/8+YwZ2za3DphlYCl85bCWKL+zVZFLnJGd+3qvA==	\N	1af89a19-55b9-42c7-8d9e-3199c61aeeaf	access_token	bearer	opaque	1671198467	1671198767	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671198467	{"__mandatory__":{"delegationId":"1af89a19-55b9-42c7-8d9e-3199c61aeeaf","exp":1671198767,"nbf":1671198467,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671198467,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":["devops"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
kaZyPbjFuN+NgOd75nHRXvKQ/LGeJjUugdfvU3qL21LQ080TXIggoBCQZkReWqdYK/klo6nm2FFtx8DpAFOWGw==	\N	413ef586-0573-4096-aa32-759460191e22	access_token	bearer	opaque	1671198475	1671198775	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	janedoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671198475	{"__mandatory__":{"delegationId":"413ef586-0573-4096-aa32-759460191e22","exp":1671198775,"nbf":1671198475,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"janedoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671198475,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":["developer"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"janedoe","_claimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
QUXA/WUgfnR8crkiPfUCaFtPPgKymqe+7+S+V/qxKty+Z5oNwfFyBJY5vwOsqYC5T9bMU9XEZ2zMNpzlazX2vQ==	\N	fc07f544-5c8f-4c43-a591-82e657e52cb5	access_token	bearer	opaque	1671198482	1671198782	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	janedoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671198482	{"__mandatory__":{"delegationId":"fc07f544-5c8f-4c43-a591-82e657e52cb5","exp":1671198782,"nbf":1671198482,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"janedoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671198482,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":["developer"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"janedoe","_claimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
n+eZh0Rfep1g0QEz5RtdS6fREUBsM2dexV8ADO0aSpSwFoMZOUnz0878SNyUH/WRRGzxs0RnQQDIfrkK3NeBGA==	\N	c63c9bed-3c96-483b-bfdb-a90af6b6c3ca	access_token	bearer	opaque	1671198494	1671198794	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671198494	{"__mandatory__":{"delegationId":"c63c9bed-3c96-483b-bfdb-a90af6b6c3ca","exp":1671198794,"nbf":1671198494,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671198494,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":["devops"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
qNtHAm1yR0SXg+Tvpl1AIDWHebxchw80NItd7nwibhDhsXSTJz09pfOkx7ekLwSoDHYjpgEIXIMCNSP9wS9t3g==	\N	7ee93507-4bdf-46db-b6d0-d1630f27e306	access_token	bearer	opaque	1671198532	1671198832	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	janedoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671198532	{"__mandatory__":{"delegationId":"7ee93507-4bdf-46db-b6d0-d1630f27e306","exp":1671198832,"nbf":1671198532,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"janedoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671198532,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":["developers"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"janedoe","_claimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
zNThLYQ8FLv/H9uM6inP6cTiIXS7+9Ps7UaBRjPxeR7/Ixk2FhDkSGKYlcAhoDOhJKgiSZRA5xe9vPtijNtKbQ==	\N	4e84e35f-6c25-41c8-8302-f401a657d130	access_token	bearer	opaque	1671198577	1671198877	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	janedoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671198577	{"__mandatory__":{"delegationId":"4e84e35f-6c25-41c8-8302-f401a657d130","exp":1671198877,"nbf":1671198577,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"janedoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671198577,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":["developers"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"janedoe","_claimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
9YL48L5dUcn/4GzsDbGdf4woTVOAtl+yZu/N7Ve8k1wunJp3BUc2uqm3SmU6Nlsgml8ZqpMTOArTK76p1GFeCA==	\N	0fb5381c-e54d-44b4-b9e8-3591446fd66a	access_token	bearer	opaque	1671198599	1671198899	openid urn:se:curity:scopes:admin:api	\N	revoked	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671198599	{"__mandatory__":{"delegationId":"0fb5381c-e54d-44b4-b9e8-3591446fd66a","exp":1671198899,"nbf":1671198599,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671198599,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":["devops"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
1c7hCPlv+OtwCgjgDFdika0u8uOvTt83Ieja6ggCCh9jSZyJloYcCZvVMe/7lJMB4DpJRf71tUqALb2zPqXuIw==	\N	665eba53-2d8c-4460-a3f7-a68a6bb6b7cf	access_token	bearer	opaque	1671198688	1671198988	openid urn:se:curity:scopes:admin:api	\N	issued	https://localhost:8443/oauth/v2/oauth-anonymous	johndoe	["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"]	1671198688	{"__mandatory__":{"delegationId":"665eba53-2d8c-4460-a3f7-a68a6bb6b7cf","exp":1671198988,"nbf":1671198688,"scope":"openid urn:se:curity:scopes:admin:api","iss":"https://localhost:8443/oauth/v2/oauth-anonymous","sub":"johndoe","aud":["urn:se:curity:audiences:admin:api","devops_dashboard_restconf_client"],"iat":1671198688,"purpose":"access_token"},"__token_class_name__":"se.curity.identityserver.tokens.data.OpaqueAccessTokenData","__optional__":{"groups":["devops"]},"__metadata__":{"_requestingClientIdentifier":{"name":"DevOps Dashboard Client","id":"devops_dashboard_restconf_client"},"_requestingSubject":"johndoe","_claimMap":{"unmappedClaims":{"groups":{"scopes":["urn:se:curity:scopes:admin:api"]},"iss":{"required":true},"sub":{"required":true},"aud":{"required":true},"exp":{"required":true},"iat":{"required":true},"auth_time":{"required":true},"nonce":{"required":true},"acr":{"required":true},"amr":{"required":true},"azp":{"required":true},"nbf":{"required":true},"client_id":{"required":true},"delegation_id":{"required":true},"purpose":{"required":true},"scope":{"required":true},"jti":{"required":true},"sid":{"required":true}}},"_isAssistedToken":false,"_clientId":"devops_dashboard_restconf_client"}}	\N
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

