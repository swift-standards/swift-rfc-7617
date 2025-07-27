//
//  RFC_7617 Tests.swift
//  RFC_7617 Tests
//
//  Created by Generated on 2025-07-27.
//

import Testing
@testable import RFC_7617

@Suite("RFC 7617 Tests")
struct RFC_7617_Tests {

    @Test("Basic credentials creation and validation")
    func testBasicCredentialsCreation() throws {
        let basic = try RFC_7617.Basic(username: "user", password: "pass")
        #expect(basic.username == "user")
        #expect(basic.password == "pass")
        
        // Test username with colon throws error
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic(username: "user:name", password: "pass")
        }
    }
    
    @Test("Basic credentials encoding")
    func testBasicCredentialsEncoding() throws {
        let basic = try RFC_7617.Basic(username: "user", password: "pass")
        let encoded = basic.encoded()
        #expect(encoded == "dXNlcjpwYXNz") // Base64 of "user:pass"
        
        let headerValue = basic.authorizationHeaderValue()
        #expect(headerValue == "Basic dXNlcjpwYXNz")
    }
    
    @Test("Basic credentials parsing from Authorization header")
    func testBasicCredentialsParsing() throws {
        let headerValue = "Basic dXNlcjpwYXNz" // "user:pass"
        let basic = try RFC_7617.Basic.parse(from: headerValue)
        #expect(basic.username == "user")
        #expect(basic.password == "pass")
        
        // Test with whitespace
        let headerWithSpaces = "  Basic dXNlcjpwYXNz  "
        let basicWithSpaces = try RFC_7617.Basic.parse(from: headerWithSpaces)
        #expect(basicWithSpaces.username == "user")
        #expect(basicWithSpaces.password == "pass")
    }
    
    @Test("Basic credentials parsing error cases")
    func testBasicCredentialsParsingErrors() {
        // Missing "Basic " prefix
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.parse(from: "Bearer dXNlcjpwYXNz")
        }
        
        // Invalid Base64
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.parse(from: "Basic invalid_base64")
        }
        
        // Missing colon separator
        let noColonBase64 = "dXNlcnBhc3M=" // Base64 of "userpass"
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.parse(from: "Basic \(noColonBase64)")
        }
    }
    
    @Test("Basic credentials with UTF-8 characters")
    func testBasicCredentialsUTF8() throws {
        let basic = try RFC_7617.Basic(username: "user", password: "páss")
        let encoded = basic.encoded()
        let decoded = try RFC_7617.Basic.parse(from: "Basic \(encoded)")
        #expect(decoded.username == "user")
        #expect(decoded.password == "páss")
    }
    
    @Test("Basic.Challenge creation and validation")
    func testBasicChallengeCreation() throws {
        let challenge = try RFC_7617.Basic.Challenge(realm: "test-realm")
        #expect(challenge.realm == "test-realm")
        #expect(challenge.charset == nil)
        
        let challengeWithCharset = try RFC_7617.Basic.Challenge(realm: "test-realm", charset: "UTF-8")
        #expect(challengeWithCharset.charset == "UTF-8")
        
        // Test invalid charset
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.Challenge(realm: "test-realm", charset: "ISO-8859-1")
        }
    }
    
    @Test("Basic.Challenge WWW-Authenticate header generation")
    func testBasicChallengeHeaderGeneration() throws {
        let challenge = try RFC_7617.Basic.Challenge(realm: "test-realm")
        let headerValue = challenge.wwwAuthenticateHeaderValue()
        #expect(headerValue == "Basic realm=\"test-realm\"")
        
        let challengeWithCharset = try RFC_7617.Basic.Challenge(realm: "test-realm", charset: "UTF-8")
        let headerValueWithCharset = challengeWithCharset.wwwAuthenticateHeaderValue()
        #expect(headerValueWithCharset == "Basic realm=\"test-realm\", charset=\"UTF-8\"")
    }
    
    @Test("Basic.Challenge parsing from WWW-Authenticate header")
    func testBasicChallengeParsing() throws {
        let headerValue = "Basic realm=\"test-realm\""
        let challenge = try RFC_7617.Basic.Challenge.parse(from: headerValue)
        #expect(challenge.realm == "test-realm")
        #expect(challenge.charset == nil)
        
        let headerValueWithCharset = "Basic realm=\"test-realm\", charset=\"UTF-8\""
        let challengeWithCharset = try RFC_7617.Basic.Challenge.parse(from: headerValueWithCharset)
        #expect(challengeWithCharset.realm == "test-realm")
        #expect(challengeWithCharset.charset == "UTF-8")
    }
    
    @Test("Basic.Challenge parsing error cases")
    func testBasicChallengeParsingErrors() {
        // Missing "Basic " prefix
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.Challenge.parse(from: "Digest realm=\"test\"")
        }
        
        // Missing realm parameter
        #expect(throws: RFC_7617.Basic.Error.self) {
            try RFC_7617.Basic.Challenge.parse(from: "Basic charset=\"UTF-8\"")
        }
    }
    
    @Test("Basic.Challenge parsing with unquoted values")
    func testBasicChallengeParsingUnquoted() throws {
        let headerValue = "Basic realm=test-realm"
        let challenge = try RFC_7617.Basic.Challenge.parse(from: headerValue)
        #expect(challenge.realm == "test-realm")
    }
    
    @Test("RFC_7617.Basic.Error localized descriptions")
    func testBasicErrorDescriptions() {
        let usernameError = RFC_7617.Basic.Error.invalidUsername("test message")
        #expect(usernameError.localizedDescription == "Invalid username: test message")
        
        let formatError = RFC_7617.Basic.Error.invalidFormat("test message")
        #expect(formatError.localizedDescription == "Invalid format: test message")
        
        let encodingError = RFC_7617.Basic.Error.invalidEncoding("test message")
        #expect(encodingError.localizedDescription == "Invalid encoding: test message")
        
        let charsetError = RFC_7617.Basic.Error.invalidCharset("test message")
        #expect(charsetError.localizedDescription == "Invalid charset: test message")
    }
    
    @Test("Edge case: empty username or password")
    func testEmptyCredentials() throws {
        let basicEmptyUsername = try RFC_7617.Basic(username: "", password: "pass")
        #expect(basicEmptyUsername.username == "")
        #expect(basicEmptyUsername.password == "pass")
        
        let basicEmptyPassword = try RFC_7617.Basic(username: "user", password: "")
        #expect(basicEmptyPassword.username == "user")
        #expect(basicEmptyPassword.password == "")
        
        // Test round-trip encoding/decoding
        let encoded = basicEmptyUsername.encoded()
        let decoded = try RFC_7617.Basic.parse(from: "Basic \(encoded)")
        #expect(decoded.username == "")
        #expect(decoded.password == "pass")
    }
    
    @Test("Edge case: password with colon")
    func testPasswordWithColon() throws {
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
