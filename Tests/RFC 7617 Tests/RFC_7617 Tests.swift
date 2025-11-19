//
//  RFC_7617 Tests.swift
//  RFC_7617 Tests
//
//  Created by Generated on 2025-07-27.
//

import Testing

@testable import RFC_7617

@Suite
struct `RFC 7617 Tests` {

    @Test
    func `Basic credentials creation and validation`() throws {
        let basic = try RFC_7617.Basic(username: "user", password: "pass")
        #expect(basic.username == "user")
        #expect(basic.password == "pass")

        // Test username with colon throws error
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic(username: "user:name", password: "pass")
        }
    }

    @Test
    func `Basic credentials encoding`() throws {
        let basic = try RFC_7617.Basic(username: "user", password: "pass")
        let encoded = basic.encoded()
        #expect(encoded == "dXNlcjpwYXNz")  // Base64 of "user:pass"

        let headerValue = basic.authorizationHeaderValue()
        #expect(headerValue == "Basic dXNlcjpwYXNz")
    }

    @Test
    func `Basic credentials parsing from Authorization header`() throws {
        let headerValue = "Basic dXNlcjpwYXNz"  // "user:pass"
        let basic = try RFC_7617.Basic.parse(from: headerValue)
        #expect(basic.username == "user")
        #expect(basic.password == "pass")

        // Test with whitespace
        let headerWithSpaces = "  Basic dXNlcjpwYXNz  "
        let basicWithSpaces = try RFC_7617.Basic.parse(from: headerWithSpaces)
        #expect(basicWithSpaces.username == "user")
        #expect(basicWithSpaces.password == "pass")
    }

    @Test
    func `Basic credentials parsing error cases`() {
        // Missing "Basic " prefix
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.parse(from: "Bearer dXNlcjpwYXNz")
        }

        // Invalid Base64
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.parse(from: "Basic invalid_base64")
        }

        // Missing colon separator
        let noColonBase64 = "dXNlcnBhc3M="  // Base64 of "userpass"
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.parse(from: "Basic \(noColonBase64)")
        }
    }

    @Test
    func `Basic credentials with UTF-8 characters`() throws {
        let basic = try RFC_7617.Basic(username: "user", password: "páss")
        let encoded = basic.encoded()
        let decoded = try RFC_7617.Basic.parse(from: "Basic \(encoded)")
        #expect(decoded.username == "user")
        #expect(decoded.password == "páss")
    }

    @Test
    func `Basic.Challenge creation and validation`() throws {
        let challenge = try RFC_7617.Basic.Challenge(realm: "test-realm")
        #expect(challenge.realm == "test-realm")
        #expect(challenge.charset == nil)

        let challengeWithCharset = try RFC_7617.Basic.Challenge(
            realm: "test-realm",
            charset: "UTF-8"
        )
        #expect(challengeWithCharset.charset == "UTF-8")

        // Test invalid charset
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.Challenge(realm: "test-realm", charset: "ISO-8859-1")
        }
    }

    @Test
    func `Basic.Challenge WWW-Authenticate header generation`() throws {
        let challenge = try RFC_7617.Basic.Challenge(realm: "test-realm")
        let headerValue = challenge.wwwAuthenticateHeaderValue()
        #expect(headerValue == "Basic realm=\"test-realm\"")

        let challengeWithCharset = try RFC_7617.Basic.Challenge(
            realm: "test-realm",
            charset: "UTF-8"
        )
        let headerValueWithCharset = challengeWithCharset.wwwAuthenticateHeaderValue()
        #expect(headerValueWithCharset == "Basic realm=\"test-realm\", charset=\"UTF-8\"")
    }

    @Test
    func `Basic.Challenge parsing from WWW-Authenticate header`() throws {
        let headerValue = "Basic realm=\"test-realm\""
        let challenge = try RFC_7617.Basic.Challenge.parse(from: headerValue)
        #expect(challenge.realm == "test-realm")
        #expect(challenge.charset == nil)

        let headerValueWithCharset = "Basic realm=\"test-realm\", charset=\"UTF-8\""
        let challengeWithCharset = try RFC_7617.Basic.Challenge.parse(from: headerValueWithCharset)
        #expect(challengeWithCharset.realm == "test-realm")
        #expect(challengeWithCharset.charset == "UTF-8")
    }

    @Test
    func `Basic.Challenge parsing error cases`() {
        // Missing "Basic " prefix
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.Challenge.parse(from: "Digest realm=\"test\"")
        }

        // Missing realm parameter
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.Challenge.parse(from: "Basic charset=\"UTF-8\"")
        }
    }

    @Test
    func `Basic.Challenge parsing with unquoted values`() throws {
        let headerValue = "Basic realm=test-realm"
        let challenge = try RFC_7617.Basic.Challenge.parse(from: headerValue)
        #expect(challenge.realm == "test-realm")
    }

    @Test
    func `RFC 7617.Basic.Error localized descriptions`() {
        let usernameError = RFC_7617.Basic.Error.invalidUsername("test message")
        #expect(usernameError.localizedDescription == "Invalid username: test message")

        let formatError = RFC_7617.Basic.Error.invalidFormat("test message")
        #expect(formatError.localizedDescription == "Invalid format: test message")

        let encodingError = RFC_7617.Basic.Error.invalidEncoding("test message")
        #expect(encodingError.localizedDescription == "Invalid encoding: test message")

        let charsetError = RFC_7617.Basic.Error.invalidCharset("test message")
        #expect(charsetError.localizedDescription == "Invalid charset: test message")
    }

    @Test
    func `Edge case: empty username or password`() throws {
        let basicEmptyUsername = try RFC_7617.Basic(username: "", password: "pass")
        #expect(basicEmptyUsername.username.isEmpty)
        #expect(basicEmptyUsername.password == "pass")

        let basicEmptyPassword = try RFC_7617.Basic(username: "user", password: "")
        #expect(basicEmptyPassword.username == "user")
        #expect(basicEmptyPassword.password.isEmpty)

        // Test round-trip encoding/decoding
        let encoded = basicEmptyUsername.encoded()
        let decoded = try RFC_7617.Basic.parse(from: "Basic \(encoded)")
        #expect(decoded.username.isEmpty)
        #expect(decoded.password == "pass")
    }

    @Test
    func `Edge case: password with colon`() throws {
        let basic = try RFC_7617.Basic(username: "user", password: "pass:word")
        #expect(basic.username == "user")
        #expect(basic.password == "pass:word")

        // Test round-trip encoding/decoding
        let encoded = basic.encoded()
        let decoded = try RFC_7617.Basic.parse(from: "Basic \(encoded)")
        #expect(decoded.username == "user")
        #expect(decoded.password == "pass:word")
    }
}
