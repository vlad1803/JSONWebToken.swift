//
//  RSA.swift
//  JWT
//
//  Created by Vlad on 12/5/17.
//  Copyright © 2017 Cocode. All rights reserved.
//

import Foundation
import CommonCrypto

func rsa(_ key: SecKey, message: Data) -> Data? {
  guard let hash = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH)) else { return nil }

  // Create SHA256 hash of the message
  CC_SHA256((message as NSData).bytes, CC_LONG(message.count), hash.mutableBytes.assumingMemoryBound(to: UInt8.self))

  // Sign the hash with the private key
  let blockSize = SecKeyGetBlockSize(key)

  let hashDataLength = Int(hash.length)
  let hashData = hash.bytes.bindMemory(to: UInt8.self, capacity: hash.length)

  guard let result = NSMutableData(length: Int(blockSize)) else { return nil }

  let encryptedData = result.mutableBytes.assumingMemoryBound(to: UInt8.self)
  var encryptedDataLength = blockSize

  let status = SecKeyRawSign(key, .PKCS1SHA256, hashData, hashDataLength, encryptedData, &encryptedDataLength)

  if status == noErr {
    // Create Base64 string of the result
    result.length = encryptedDataLength
    return result as Data
  }

  return nil
}
