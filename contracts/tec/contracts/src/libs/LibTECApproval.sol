/*

  Copyright 2018 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.3;

import "./LibEIP712Domain.sol";


contract LibTECApproval is
    LibEIP712Domain
{
    // Hash for the EIP712 TEC approval message
    // keccak256(abi.encodePacked(
    //     "TECApproval(",
    //     "address txOrigin,",
    //     "bytes32 transactionHash,",
    //     "bytes transactionSignature,",
    //     "uint256 approvalExpirationTimeSeconds",
    //     ")"
    // ));
    bytes32 constant internal EIP712_TEC_APPROVAL_SCHEMA_HASH = 0xbe1e90d67a84d7bb7130d6749e4335e8265c0f1048ae04cc2f55e395e22aaab5;

    struct TECApproval {
        address txOrigin;                       // Required signer of Ethereum transaction that is submitting approval.
        bytes32 transactionHash;                // EIP712 hash of the transaction, using the domain separator of this contract.
        bytes transactionSignature;             // Signature of the 0x transaction.
        uint256 approvalExpirationTimeSeconds;  // Timestamp in seconds for which the signature expires.
    }

    /// @dev Calculated the EIP712 hash of the TEC approval mesasage using the domain separator of this contract.
    /// @param approval TEC approval message containing the transaction hash, transaction signature, and expiration of the approval.
    /// @return EIP712 hash of the TEC approval message with the domain separator of this contract.
    function getTECApprovalHash(TECApproval memory approval)
        internal
        view
        returns (bytes32 approvalHash)
    {
        approvalHash = hashEIP712Message(hashTECApproval(approval));
        return approvalHash;
    }

    /// @dev Calculated the EIP712 hash of the TEC approval mesasage with no domain separator.
    /// @param approval TEC approval message containing the transaction hash, transaction signature, and expiration of the approval.
    /// @return EIP712 hash of the TEC approval message with no domain separator.
    function hashTECApproval(TECApproval memory approval)
        internal
        pure
        returns (bytes32 result)
    {
        bytes32 schemaHash = EIP712_TEC_APPROVAL_SCHEMA_HASH;
        bytes memory transactionSignature = approval.transactionSignature;
        address txOrigin = approval.txOrigin;
        bytes32 transactionHash = approval.transactionHash;
        uint256 approvalExpirationTimeSeconds = approval.approvalExpirationTimeSeconds;

        // Assembly for more efficiently computing:
        // keccak256(abi.encodePacked(
        //     EIP712_TEC_APPROVAL_SCHEMA_HASH,
        //     approval.transactionHash,
        //     keccak256(approval.transactionSignature)
        //     approval.expiration,
        // ));

        assembly {
            // Compute hash of transaction signature
            let transactionSignatureHash := keccak256(add(transactionSignature, 32), mload(transactionSignature))
        
            // Load free memory pointer
            let memPtr := mload(64)

            mstore(memPtr, schemaHash)                               // hash of schema
            mstore(add(memPtr, 32), txOrigin)                        // txOrigin
            mstore(add(memPtr, 64), transactionHash)                 // transactionHash
            mstore(add(memPtr, 96), transactionSignatureHash)        // transactionSignatureHash
            mstore(add(memPtr, 128), approvalExpirationTimeSeconds)  // approvalExpirationTimeSeconds
            // Compute hash
            result := keccak256(memPtr, 160)
        }
        return result;
    }
}
