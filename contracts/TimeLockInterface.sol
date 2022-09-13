
// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

interface TimeLockInterface {
    function confirmDecryptedSecret(string memory ipfs, uint256 index, bool verdict) external;
    function submitDecryptionKey(string memory _ipfs, string memory _decryptionKey) external;
}