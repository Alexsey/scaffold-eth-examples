// SPDX-License-Identifier: MIT

//  Off-chain signature gathering multisig that streams funds - @austingriffith
//
// started from 🏗 scaffold-eth - meta-multi-sig-wallet example https://github.com/austintgriffith/scaffold-eth/tree/meta-multi-sig
//    (off-chain signature based multi-sig)
//  added a very simple streaming mechanism where `onlySelf` can open a withdraw-based stream
//

pragma solidity >=0.8.0 <0.9.0;
// Not needed to be explicitly imported in Solidity 0.8.x
// pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MetaMultiSigWallet {
  using ECDSA for bytes32;

  event Deposit(address indexed sender, uint amount, uint balance);
  event ExecuteTransaction(
    address owner, address to,
    uint value, bytes data,
    uint nonce, bytes32 hash,
    bytes result
  );
  event Owner(address owner, bool vote);

  uint public chainId;
  uint public nonce;

  uint public signaturesRequired;
  mapping (address => bool) public isOwner;

  constructor(uint _chainId, address[] memory _owners, uint _signaturesRequired) {
    require(_signaturesRequired > 0, "Signatures required must be more than zero");

    chainId = _chainId;
    signaturesRequired = _signaturesRequired;

    for (uint i = 0; i < _owners.length; i++) {
      address owner = _owners[i];

      require(owner != address(0), "Owner cannot be zero address");
      require(!isOwner[owner], string(abi.encodePacked("Duplicate owner ", owner)));

      isOwner[owner] = true;

      emit Owner(owner, true);
    }
  }

  function addSigner(address _signer, uint _signaturesRequired) public onlySelf {
    require(_signer != address(0), "Signer cannot be zero address");
    require(!isOwner[_signer], string(abi.encodePacked(
        "Address ", _signer, " is already an owner"
    )));
    require(_signaturesRequired > 0, "Number of signers must be more then 0");

    signaturesRequired = _signaturesRequired;
    isOwner[_signer] = true;

    emit Owner(_signer, true);
  }

  function removeSigner(address _signer, uint _signaturesRequired) public onlySelf {
    require(isOwner[_signer], string(abi.encodePacked("Address ", _signer, " is not an owner")));
    require(_signaturesRequired > 0, "Number of signers must be more then 0");

    isOwner[_signer] = false;
    signaturesRequired = _signaturesRequired;

    emit Owner(_signer, false);
  }

  function transferFunds(address payable _receiver, uint _amount) public onlySelf {
    require(_amount <= address(this).balance, string(abi.encodePacked(
      "Cannot transfer ", _amount, " because balance is only ", address(this).balance
    )));

    _receiver.call{value: _amount}("");
  }

  function updateSignaturesRequired(uint _signaturesRequired) public onlySelf {
    require(_signaturesRequired > 0, "Number or required signatures must be greater than zero");

    signaturesRequired = _signaturesRequired;
  }

  function getTransactionHash(
    uint _nonce,
    address to,
    uint value,
    bytes memory data
  )
    public view
    returns (bytes32)
  {
    return keccak256(abi.encodePacked(address(this), chainId, _nonce, to, value, data));
  }

  function executeTransaction(
    address payable to,
    uint value,
    bytes memory data,
    bytes[] memory signatures)
      public
      returns (bytes memory)
  {
    require(isOwner[msg.sender], "executeTransaction: only owners can execute");

    bytes32 hash = getTransactionHash(nonce, to, value, data);
    nonce++;

    uint signers;
    address duplicateGuard;
    for (uint i = 0; i < signatures.length; i++) {
      address signer = recover(hash, signatures[i]);
      require(signer > duplicateGuard, string(abi.encodePacked(
          "Duplicate or unordered signer ", signer
      )));
      duplicateGuard = signer;

      if (isOwner[signer]) signers++;
    }

    require(signers >= signaturesRequired, "Not enough owner's signatures");

    (bool isSuccess, bytes memory res) = to.call{value: value}(data);
    require(isSuccess, "Transaction execution failed");

    emit ExecuteTransaction(msg.sender, to, value, data, nonce - 1, hash, res);

    return res;
  }

  function recover(bytes32 _hash, bytes memory _signature) public pure returns (address) {
    return _hash.toEthSignedMessageHash().recover(_signature);
  }

  modifier onlySelf () {
    require(msg.sender == address(this), "Not self");
    _;
  }

  receive() payable external {
    emit Deposit(msg.sender, msg.value, address(this).balance);
  }
}
