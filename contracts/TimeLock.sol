// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "@openzeppelin/contracts/access/Ownable.sol";

contract TimeLock is Ownable {
    // Boolean variable used to pause the contract
    bool private paused = false;

    struct FileDetails {
        string fileName;
        uint256 totalShares;
        uint256 minimumNumberOfShares;
        address fileOwner;
        string[] uploadedDecryptedSecrets;
        uint256 unlockTime;
        uint256 biddingTime;
        uint256 reward;
    }

    // Mapping containing all the details for each IPFS Hash
    mapping(string => FileDetails) private ipfsDetails;

    struct HiddenSecretMapping {
        string secret;
        bytes32 keccakCheck;
        bool allowed;
    }
    // For each IPFS hash store a mapping from each secret share holder address to the secret
    mapping(string => mapping(address => HiddenSecretMapping))
        private ipfsToSecrets;

    struct HiddenSecret {
        address holder;
        string secretShare;
        bytes32 keccakCheck;
    }

    // For each IPFS hash store an array containing a pair of holders with the corresponding share
    mapping(string => HiddenSecret[]) private ipfsHashToHolderDetails;

    // Store the public key of each share holder
    mapping(address => string) private shareHolderToPublicKey;

    struct DecryptedSecret {
        string secret;
        address payable submitter;
    }

    struct DecryptedSecrets {
        uint256 validSubmitted;
        DecryptedSecret[] secrets;
    }

    // Store the decrypted secrets for each IPFS hash
    mapping(string => DecryptedSecrets) private ipfsToDecryptedSecrets;

    // Store the detected cheaters' address
    mapping(string => mapping(address => bool)) private ipfsToCheaters;

    // For each ipfsHash hash store an array containing the holder and corresponding provided collateral
    struct Collateral {
        address payable holder;
        uint256 amount;
    }
    mapping(string => Collateral[]) private collaterals;
    mapping(string => mapping(address => uint256)) private providedCollaterals;

    event NewDecrypted(
        string ipfsHash,
        address submitter,
        string deryptedSecret,
        string encryptedSecret,
        uint256 index,
        string publicKey
    );

    event ReadyToRebuildKey(string ipfsHash, string[] shares);

    event NewTimeLock(
        string ipfsHash,
        string fileName,
        address owner,
        uint256 biddingTime,
        uint256 unlockTime,
        uint256 totalAmount,
        uint256 reward
    );

    event NewEncrypted(string ipfsHash, string secretShare, address holder);

    event NewHigherBid(string ipfsHash, uint256 shareIndex, uint256 amount);

    modifier assignedToIpfs(string memory ipfsHash) {
        require(
            ipfsToSecrets[ipfsHash][msg.sender].allowed,
            "You are not assigned to this IPFS hash"
        );
        _;
    }

    modifier isNotPaused() {
        require(!paused, "Smart contract is paused");
        _;
    }

    modifier onlyFileOwner(string memory _ipfsHash) {
        require(
            msg.sender == ipfsDetails[_ipfsHash].fileOwner,
            "You are not the owner of this file"
        );
        _;
    }

    modifier duringBidding(string memory _ipfsHash) {
        require(
            block.timestamp <= ipfsDetails[_ipfsHash].biddingTime,
            "Bidding time is over"
        );
        _;
    }

    modifier higherCollateral(
        string memory _ipfsHash,
        uint256 _shareIndex,
        uint256 _amount
    ) {
        require(
            collaterals[_ipfsHash][_shareIndex].amount < _amount,
            "The provided collateral must be larger than the current one"
        );
        _;
    }

    modifier singleBid(string memory _ipfsHash, address sender) {
        require(
            providedCollaterals[_ipfsHash][sender] == 0,
            "You are only allowed to have one active bid per IPFS hash"
        );
        _;
    }

    modifier duringTimeLock(uint256 unlockTime) {
        require(block.timestamp < unlockTime, "The time-lock has not started");
        _;
    }

    modifier timeLockIsOver(uint256 unlockTime) {
        require(block.timestamp >= unlockTime, "The time-lock is not over");
        _;
    }

    modifier keccakMatch(string memory ipfsHash, string memory secret) {
        require(
            keccak256(bytes(secret)) ==
                ipfsToSecrets[ipfsHash][msg.sender].keccakCheck,
            "keccak does not match"
        );
        _;
    }

    modifier submittedOnce(string memory ipfsHash, string memory secret) {
        for (
            uint256 i = 0;
            i < ipfsToDecryptedSecrets[ipfsHash].validSubmitted;
            i++
        ) {
            // Make sure the secret has not been submitted again
            require(
                keccak256(
                    bytes(ipfsToDecryptedSecrets[ipfsHash].secrets[i].secret)
                ) != keccak256(bytes(secret)),
                "You cannot submit the same secret multiple times"
            );
        }

        _;
    }

    // Pause of unpause the smart contract
    function modifyPauseState(bool _paused) public onlyOwner {
        paused = _paused;
    }

    // Starting a new time-lock
    function timeLockNewFile(
        string memory _ipfsHash,
        string memory _fileName,
        uint256 _totalShares,
        uint256 _minimumNumberOfShares,
        uint256 _unlockTime,
        uint256 _biddingTime
    ) public payable isNotPaused {
        // Store the details
        ipfsDetails[_ipfsHash].fileName = _fileName;
        ipfsDetails[_ipfsHash].totalShares = _totalShares;
        ipfsDetails[_ipfsHash].minimumNumberOfShares = _minimumNumberOfShares;
        ipfsDetails[_ipfsHash].fileOwner = msg.sender;
        ipfsDetails[_ipfsHash].biddingTime = block.timestamp + _biddingTime;
        ipfsDetails[_ipfsHash].unlockTime =
            block.timestamp +
            _biddingTime +
            _unlockTime;
        ipfsDetails[_ipfsHash].reward = msg.value;

        // Initialise the collaterals
        for (uint256 i = 0; i < _totalShares; ++i) {
            collaterals[_ipfsHash].push(Collateral(payable(address(0)), 0));
        }

        emit NewTimeLock(
            _ipfsHash,
            _fileName,
            msg.sender,
            ipfsDetails[_ipfsHash].biddingTime,
            ipfsDetails[_ipfsHash].unlockTime,
            _totalShares,
            msg.value
        );
    }

    // Register a higher bid for a specific index of an IPFS hash
    function bidCollateral(string memory _ipfsHash, uint256 _shareIndex)
        public
        payable
        duringBidding(_ipfsHash)
        higherCollateral(_ipfsHash, _shareIndex, msg.value)
        singleBid(_ipfsHash, msg.sender)
        isNotPaused
    {
        // Transfer the coins back to the previous bidder
        require(
            collaterals[_ipfsHash][_shareIndex].holder.send(
                collaterals[_ipfsHash][_shareIndex].amount
            ),
            "Failed to refund collateral"
        );

        // Record the provided collateral
        providedCollaterals[_ipfsHash][msg.sender] = msg.value;
        providedCollaterals[_ipfsHash][
            collaterals[_ipfsHash][_shareIndex].holder
        ] = 0;

        // Update the highest bidder and emit the required event to update the frontend
        collaterals[_ipfsHash][_shareIndex] = Collateral(
            payable(msg.sender),
            msg.value
        );
        emit NewHigherBid(_ipfsHash, _shareIndex, msg.value);
    }

    function getCollateral(string memory _ipfsHash, uint256 _shareIndex)
        public
        view
        returns (uint256)
    {
        return collaterals[_ipfsHash][_shareIndex].amount;
    }

    function getBidders(string memory _ipfsHash)
        public
        view
        returns (address[] memory)
    {
        uint256 biddersSize = ipfsDetails[_ipfsHash].totalShares;

        address[] memory bidders = new address[](biddersSize);

        for (uint256 i = 0; i < biddersSize; i++) {
            bidders[i] = collaterals[_ipfsHash][i].holder;
        }

        return bidders;
    }

    // Submit an encrypted secret
    function submitEncrypted(
        string memory ipfsHash,
        string memory secretShare,
        bytes32 keccakCheck,
        address holder
    ) public onlyFileOwner(ipfsHash) isNotPaused {
        ipfsToSecrets[ipfsHash][holder].secret = secretShare;
        ipfsToSecrets[ipfsHash][holder].keccakCheck = keccakCheck;
        ipfsToSecrets[ipfsHash][holder].allowed = true;

        ipfsHashToHolderDetails[ipfsHash].push(
            HiddenSecret(holder, secretShare, keccakCheck)
        );

        emit NewEncrypted(ipfsHash, secretShare, holder);
    }

    // Submit a batch of encrypted secrets to save gas
    function submitEncryptedSecrets(
        string memory ipfsHash,
        string[] memory secretShares,
        bytes32[] memory keccakChecks
    )
        public
        onlyFileOwner(ipfsHash)
        isNotPaused
        duringTimeLock(ipfsDetails[ipfsHash].unlockTime)
    {
        for (uint256 i = 0; i < ipfsDetails[ipfsHash].totalShares; ++i) {
            address holder = collaterals[ipfsHash][i].holder;
            string memory secretShare = secretShares[i];
            bytes32 keccakCheck = keccakChecks[i];

            submitEncrypted(ipfsHash, secretShare, keccakCheck, holder);
        }
    }

    // Submit a public key
    function submitPublicKey(string memory _publicKey) public isNotPaused {
        shareHolderToPublicKey[msg.sender] = _publicKey;
    }

    function getPublicKey(address _shareHolder)
        public
        view
        returns (string memory)
    {
        return shareHolderToPublicKey[_shareHolder];
    }

    function getSecret(string memory ipfsHash)
        public
        view
        assignedToIpfs(ipfsHash)
        returns (string memory)
    {
        return ipfsToSecrets[ipfsHash][msg.sender].secret;
    }

    // Submit a decrypted secret after the time-lock deadline
    function submitDecrypted(string memory ipfsHash, string memory secret)
        public
        timeLockIsOver(ipfsDetails[ipfsHash].unlockTime)
        assignedToIpfs(ipfsHash)
        keccakMatch(ipfsHash, secret)
        submittedOnce(ipfsHash, secret)
        isNotPaused
    {
        // Check if the keccak hashes match
        if (
            keccak256(bytes(secret)) ==
            ipfsToSecrets[ipfsHash][msg.sender].keccakCheck
        ) {
            ipfsToDecryptedSecrets[ipfsHash].secrets.push(
                DecryptedSecret(secret, payable(msg.sender))
            );

            ipfsToDecryptedSecrets[ipfsHash].validSubmitted++;

            // Check if the key can be rebuilt
            if (
                ipfsToDecryptedSecrets[ipfsHash].validSubmitted ==
                ipfsDetails[ipfsHash].minimumNumberOfShares
            ) {
                string[] memory returnedSecrets = new string[](
                    ipfsDetails[ipfsHash].minimumNumberOfShares
                );
                for (
                    uint256 i = 0;
                    i < ipfsToDecryptedSecrets[ipfsHash].validSubmitted;
                    i++
                ) {
                    // Store the secrets in order to emit them in the event
                    returnedSecrets[i] = ipfsToDecryptedSecrets[ipfsHash]
                        .secrets[i]
                        .secret;

                    // If a confirmed cheater submitted a secret share, do not give the reward
                    if (
                        ipfsToCheaters[ipfsHash][
                            ipfsToDecryptedSecrets[ipfsHash]
                                .secrets[i]
                                .submitter
                        ]
                    ) {
                        continue;
                    }

                    // Reward the share holder
                    require(
                        ipfsToDecryptedSecrets[ipfsHash]
                            .secrets[i]
                            .submitter
                            .send(
                                ipfsDetails[ipfsHash].reward /
                                    ipfsDetails[ipfsHash].minimumNumberOfShares
                            ),
                        "Reward payment failed"
                    );
                }

                // Pay back the collaterals
                for (uint256 i = 0; i < collaterals[ipfsHash].length; ++i) {
                    require(
                        collaterals[ipfsHash][i].holder.send(
                            providedCollaterals[ipfsHash][
                                collaterals[ipfsHash][i].holder
                            ]
                        ),
                        "Collateral payment failed"
                    );
                }

                // Emit a new event containing all decrypted shares
                emit ReadyToRebuildKey(ipfsHash, returnedSecrets);
            } else {
                emit NewDecrypted(
                    ipfsHash,
                    msg.sender,
                    secret,
                    ipfsToSecrets[ipfsHash][msg.sender].secret,
                    ipfsToDecryptedSecrets[ipfsHash].secrets.length - 1,
                    shareHolderToPublicKey[msg.sender]
                );
            }
        } else {
            // The share holder submitted something useless
            revert();
        }
    }

    // Function used to report a malicious share holder
    function reportCheater(
        string memory ipfsHash,
        string memory decryptedSecret
    ) public duringTimeLock(ipfsDetails[ipfsHash].unlockTime) isNotPaused {
        bytes32 keccakSecret = keccak256(bytes(decryptedSecret));
        bool check = false;
        address cheater = address(0);

        // Check whether a keccak hash matches the reported share's hash
        // and find the cheater's address
        for (
            uint256 i = 0;
            i < ipfsHashToHolderDetails[ipfsHash].length && !check;
            ++i
        ) {
            check =
                check ||
                (keccakSecret ==
                    ipfsHashToHolderDetails[ipfsHash][i].keccakCheck);
            if (check) {
                cheater = ipfsHashToHolderDetails[ipfsHash][i].holder;
            }
        }

        require(cheater != msg.sender, "You cannot report your own key");
        require(
            check,
            "The secret you submitted is not used for this time-lock"
        );
        require(cheater != address(0), "No cheater found");
        require(
            !ipfsToCheaters[ipfsHash][cheater],
            "You cannot report the same cheater multiple times"
        );

        // Register the cheater
        ipfsToCheaters[ipfsHash][cheater] = true;

        // Add half of the cheater's collateral to the time-lock reward
        ipfsDetails[ipfsHash].reward +=
            providedCollaterals[ipfsHash][cheater] /
            2;

        // Pay the user who reported the leak
        address payable reporter = payable(msg.sender);

        require(
            reporter.send(providedCollaterals[ipfsHash][cheater] / 2),
            "You found a cheater but you could not get the reward, try again"
        );

        // Confiscate the cheater's collateral
        providedCollaterals[ipfsHash][cheater] = 0;
    }

    function getDecryptedSecrets(string memory ipfsHash)
        public
        view
        returns (string[] memory)
    {
        string[] memory returnedSecrets = new string[](
            ipfsDetails[ipfsHash].minimumNumberOfShares
        );
        for (
            uint256 i = 0;
            i < ipfsToDecryptedSecrets[ipfsHash].validSubmitted;
            i++
        ) {
            returnedSecrets[i] = ipfsToDecryptedSecrets[ipfsHash]
                .secrets[i]
                .secret;
        }
        return returnedSecrets;
    }

    function getIpfsDecryptedSecrets(string memory ipfsHash)
        public
        view
        returns (DecryptedSecrets memory)
    {
        return ipfsToDecryptedSecrets[ipfsHash];
    }

    // Withdraw the funds locked in the smart contract in case of an emergency
    function withdrawFunds(address payable receiver) public onlyOwner {
        require(
            receiver.send(address(this).balance),
            "Failed to withdraw funds"
        );
    }
}
