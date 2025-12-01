// ===----------------------------------------------------------------------===//
//
// This source file is part of the swift-rfc-7617 open source project
//
// Copyright (c) 2025 Coen ten Thije Boonkkamp
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
// ===----------------------------------------------------------------------===//

/// RFC 7617: The 'Basic' HTTP Authentication Scheme
///
/// This specification defines the "Basic" Hypertext Transfer Protocol (HTTP)
/// authentication scheme, which transmits credentials as user-id/password pairs,
/// encoded using Base64.
///
/// ## Key Types
///
/// - ``Basic``: HTTP Basic Authentication credentials (user-id and password)
/// - ``Basic.Challenge``: WWW-Authenticate challenge parameters
///
/// ## Example
///
/// ```swift
/// // Create credentials
/// let credentials = try RFC_7617.Basic(userID: "Aladdin", password: "open sesame")
///
/// // Serialize to Authorization header
/// let header = String(credentials)  // "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
///
/// // Parse from Authorization header
/// let parsed = try RFC_7617.Basic(ascii: "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==".utf8)
/// ```
///
/// ## See Also
///
/// - [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617)
/// - [RFC 7235](https://www.rfc-editor.org/rfc/rfc7235) (HTTP Authentication)
public enum RFC_7617 {}
