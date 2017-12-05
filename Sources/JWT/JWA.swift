import Foundation

/// Represents a JSON Web Algorithm (JWA)
/// https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
public enum Algorithm: CustomStringConvertible {
  /// No Algorithm, i-e, insecure
  case none

  /// HMAC using SHA-256 hash algorithm
  case hs256(Data)

  /// HMAC using SHA-384 hash algorithm
  case hs384(Data)

  /// HMAC using SHA-512 hash algorithm
  case hs512(Data)

  /// RSA using SHA-256 hash algorithm
  case rs256(SecKey)

  public var description: String {
    switch self {
    case .none:
      return "none"
    case .hs256:
      return "HS256"
    case .hs384:
      return "HS384"
    case .hs512:
      return "HS512"
    case .rs256:
      return "RS256"
    }
  }

  /// Sign a message using the algorithm
  func sign(_ message: String) -> String {
    func signHS(_ key: Data, algorithm: HMACAlgorithm) -> String {
      let messageData = message.data(using: String.Encoding.utf8, allowLossyConversion: false)!
      return base64encode(hmac(algorithm: algorithm, key: key, message: messageData))
    }

    func signRS(_ keyData: SecKey) -> String {
      let messageData = message.data(using: String.Encoding.utf8, allowLossyConversion: false)!

      return base64encode(rsa(key, message: messageData)!)
    }

    switch self {
    case .none:
      return ""

    case .hs256(let key):
      return signHS(key, algorithm: .sha256)

    case .hs384(let key):
      return signHS(key, algorithm: .sha384)

    case .hs512(let key):
      return signHS(key, algorithm: .sha512)
    case .rs256(let key):
      return signRS(key)
    }
  }

  /// Verify a signature for a message using the algorithm
  func verify(_ message: String, signature: Data) -> Bool {
    return sign(message) == base64encode(signature)
  }
}
