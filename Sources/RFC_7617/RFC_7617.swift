//
//  RFC_7617.swift
//  swift-rfc-7617
//
//  Created by Generated on 2025-07-27.
//

import Foundation

/// Implementation of RFC 7617: The 'Basic' HTTP Authentication Scheme
///
/// See: https://www.rfc-editor.org/rfc/rfc7617.html
public enum RFC_7617 {
    /// Represents HTTP Basic Authentication credentials according to RFC 7617
    public struct Basic: Codable, Hashable, Sendable {
        public let username: String
        public let password: String

        /// Creates Basic authentication credentials
        /// - Parameters:
        ///   - username: The user identifier (cannot contain colon character)
        ///   - password: The password
        /// - Throws: `Error.invalidUsername` if username contains colon
        public init(username: String, password: String) throws {
            guard !username.contains(":") else {
                throw Error.invalidUsername("Username cannot contain colon character")
            }
            self.username = username
            self.password = password
        }
    }
}

extension RFC_7617.Basic {
    /// Creates Basic authentication credentials without validation (for internal use)
    internal init(uncheckedUsername: String, password: String) {
        self.username = uncheckedUsername
        self.password = password
    }

    /// Encodes credentials as Base64 string for Authorization header
    /// - Parameter charset: Character encoding to use (defaults to UTF-8)
    /// - Returns: Base64-encoded credentials string
    public func encoded(charset: CharacterSet = .utf8) -> String {
        let credentials = "\(username):\(password)"
        let data = credentials.data(using: .utf8) ?? Data()
        return data.base64EncodedString()
    }

    /// Creates Authorization header value
    /// - Returns: Complete Authorization header value with "Basic " prefix
    public func authorizationHeaderValue() -> String {
        return "Basic \(encoded())"
    }

    /// Parses Basic authentication from Authorization header value
    /// - Parameter headerValue: The Authorization header value
    /// - Returns: Basic credentials if valid
    /// - Throws: `Error` for invalid format or encoding
    public static func parse(from headerValue: String) throws -> RFC_7617.Basic {
        let trimmed = headerValue.trimmingCharacters(in: .whitespacesAndNewlines)

        guard trimmed.lowercased().hasPrefix("basic ") else {
            throw Error.invalidFormat("Authorization header must start with 'Basic '")
        }

        let base64String = String(trimmed.dropFirst(6))
        guard let data = Data(base64Encoded: base64String),
            let decodedString = String(data: data, encoding: .utf8)
        else {
            throw Error.invalidEncoding("Invalid Base64 encoding or UTF-8 decoding")
        }

        guard let colonIndex = decodedString.firstIndex(of: ":") else {
            throw Error.invalidFormat("Credentials must contain colon separator")
        }

        let username = String(decodedString[..<colonIndex])
        let password = String(decodedString[decodedString.index(after: colonIndex)...])

        return RFC_7617.Basic(uncheckedUsername: username, password: password)
    }

    public enum CodingKeys: CodingKey {
        case username
        case password
    }
}

extension RFC_7617.Basic {
    /// Represents a Basic authentication challenge from WWW-Authenticate header
    public struct Challenge: Codable, Hashable, Sendable {
        public let realm: String
        public let charset: String?

        /// Creates a Basic authentication challenge
        /// - Parameters:
        ///   - realm: The protection space identifier (required)
        ///   - charset: Optional character encoding (only "UTF-8" is valid per RFC)
        public init(realm: String, charset: String? = nil) throws {
            if let charset = charset, charset.uppercased() != "UTF-8" {
                throw Error.invalidCharset("Only UTF-8 charset is supported")
            }
            self.realm = realm
            self.charset = charset
        }

        /// Creates WWW-Authenticate header value
        /// - Returns: Complete WWW-Authenticate header value
        public func wwwAuthenticateHeaderValue() -> String {
            var value = "Basic realm=\"\(realm)\""
            if let charset = charset {
                value += ", charset=\"\(charset)\""
            }
            return value
        }

        /// Parses Basic challenge from WWW-Authenticate header
        /// - Parameter headerValue: The WWW-Authenticate header value
        /// - Returns: Basic.Challenge if valid
        /// - Throws: `Error` for invalid format
        public static func parse(from headerValue: String) throws -> RFC_7617.Basic.Challenge {
            let trimmed = headerValue.trimmingCharacters(in: .whitespacesAndNewlines)

            guard trimmed.lowercased().hasPrefix("basic ") else {
                throw Error.invalidFormat("WWW-Authenticate header must start with 'Basic '")
            }

            let parameters = String(trimmed.dropFirst(6))
            var realm: String?
            var charset: String?

            // Simple parameter parsing (could be enhanced for more complex cases)
            let components = parameters.components(separatedBy: ",")
            for component in components {
                let trimmedComponent = component.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmedComponent.lowercased().hasPrefix("realm=") {
                    realm = extractQuotedValue(from: trimmedComponent, parameter: "realm")
                } else if trimmedComponent.lowercased().hasPrefix("charset=") {
                    charset = extractQuotedValue(from: trimmedComponent, parameter: "charset")
                }
            }

            guard let realmValue = realm else {
                throw Error.invalidFormat("realm parameter is required")
            }

            return try RFC_7617.Basic.Challenge(realm: realmValue, charset: charset)
        }

        private static func extractQuotedValue(from component: String, parameter: String) -> String? {
            let prefix = "\(parameter)="
            guard component.lowercased().hasPrefix(prefix.lowercased()) else { return nil }

            let value = String(component.dropFirst(prefix.count)).trimmingCharacters(
                in: .whitespacesAndNewlines
            )
            if value.hasPrefix("\"") && value.hasSuffix("\"") {
                return String(value.dropFirst().dropLast())
            }
            return value
        }
    }
}

extension RFC_7617.Basic {
    /// Errors that can occur during Basic authentication operations
    public enum Error: Swift.Error, Codable, Hashable, Sendable {
        case invalidUsername(String)
        case invalidFormat(String)
        case invalidEncoding(String)
        case invalidCharset(String)

        public var localizedDescription: String {
            switch self {
            case .invalidUsername(let message):
                return "Invalid username: \(message)"
            case .invalidFormat(let message):
                return "Invalid format: \(message)"
            case .invalidEncoding(let message):
                return "Invalid encoding: \(message)"
            case .invalidCharset(let message):
                return "Invalid charset: \(message)"
            }
        }
    }
}

extension CharacterSet {
    public static let utf8 = CharacterSet()
}
