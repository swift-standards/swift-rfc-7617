//
//  ReadmeVerificationTests.swift
//  swift-rfc-7617
//
//  Verifies that README code examples actually work
//

import RFC_7617
import Testing

@Suite("README Verification")
struct ReadmeVerificationTests {

    @Test("README Line 53-61: Create Basic authentication credentials")
    func createBasicCredentials() throws {
        let credentials = try RFC_7617.Basic(username: "user", password: "pass")

        let authHeader = credentials.authorizationHeaderValue()
        #expect(authHeader == "Basic dXNlcjpwYXNz")

        let encoded = credentials.encoded()
        #expect(encoded == "dXNlcjpwYXNz")
    }

    @Test("README Line 67-71: Parse credentials from Authorization header")
    func parseAuthorizationHeader() throws {
        let headerValue = "Basic dXNlcjpwYXNz"
        let credentials = try RFC_7617.Basic.parse(from: headerValue)
        #expect(credentials.username == "user")
        #expect(credentials.password == "pass")
    }

    @Test("README Line 77-87: Create authentication challenges")
    func createAuthenticationChallenges() throws {
        let challenge = try RFC_7617.Basic.Challenge(realm: "api")

        let wwwAuthHeader = challenge.wwwAuthenticateHeaderValue()
        #expect(wwwAuthHeader == "Basic realm=\"api\"")

        let utf8Challenge = try RFC_7617.Basic.Challenge(realm: "api", charset: "UTF-8")
        let utf8Header = utf8Challenge.wwwAuthenticateHeaderValue()
        #expect(utf8Header == "Basic realm=\"api\", charset=\"UTF-8\"")
    }

    @Test("README Line 93-97: Parse challenge from WWW-Authenticate header")
    func parseWWWAuthenticateHeader() throws {
        let headerValue = "Basic realm=\"api\", charset=\"UTF-8\""
        let challenge = try RFC_7617.Basic.Challenge.parse(from: headerValue)
        #expect(challenge.realm == "api")
        #expect(challenge.charset == "UTF-8")
    }
}
