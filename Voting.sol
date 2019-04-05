pragma solidity ^0.5.0

import "./SECP256K!.sol"
import "./LinkableRingSignature.sol"

contract Voting {

    /**********************************
        Constants for Crypto
    **********************************/

    uint constant pp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // Base point (generator) G
    uint constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    // Order of G
    uint constant nn = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    int stage;
    address private ElectionAuthority;
    /*
    Stage values : -

    0 --> Setup
    1 --> Registration
    2 -->  Voting
    3 --> Finished
    4 --> Ready to Tally
    */

    /**********************************
        Some Values to set on Setup
    ************************************/

    uint public constant maxVotersPerRing = 500;
    uint public numVotersPerRing;

    uint public numVotingOptions;

    uint public t;
    uint public n'

    //For threshold crypto

    uint256[2][] public secretShareVerifyPublicParams;
    mapping(uint256 => bool) public registeredSubSecrets;
    uint256[] public secretShare;
    uint256[2] public thresholdKey;
    uint356 public reconstructedKey = 0;

    /****************************************
        To be filled during Registration
    ****************************************/
    uint public currentRingNo;
    mapping(uint => uint256[]) public ring;

    uint256[2][] public voters;
    mapping(uint256 => uint) public hashRingtoNo;
    mapping(bytes32 => bool) public registeredKeys;
    mapping(bytes32 => uint) public hashKeytoRingNo;
    
    /*******************************************
        Data for Voting
    *******************************************/

    uint256[3][] public encryptedVotes;
    mapping(bytes32 => uint) public registeredVoteLink;

    constructor() public {
        ElectionAuthority = msg.sender;
        state = 0;
        currentRingNo = 1;
    }

    function setUpElection(
        uint _numVotersPerRing,
        uint _numVotingOptions,
        uint _t,
        uint _n,
        uint256[2][] _secretShareVerifyPublicParams,
        uint256[2] _thresholdKey) returns bool {
            require(state == 0 , "Not in Setup Stage");
            require(ElectionAuthority == msg.sender , "Only Election Authority Allowed");
            require(_numVotersPerRing < maxVotersPerRing, "Max voters in a ring is 500");
            require(Secp256k1.isPubKey(_thresholdKey), "Thresholdkey not a pubkey");

            for(int i = 0 ; i < _secretShareVerifyPublicParams.length ; i++)
            {
                require(Secp256k1.isPubKey(_secretShareVerifyPublicParams[i]),"Not Public Key");
            }

            require(_t == _secretShareVerifyPublicParams.length,"Size mismatch");
            require(_numVotingOptions >= 2 , "Voting Options cannot be less than 2");

            numVotersPerRing = _numVotersPerRing;
            numVotingOptions = _numVotingOptions;
            t = _t;
            n = _n;

            for(int i = 0 ; i < n ; i++)
            {
                secretShare.push(0);
            }

            secretShareVerifyPublicParams = _secretShareVerifyPublicParams;
            thresholdKey = _thresholdKey;
            state = 1;

            return true;


        }

        function registerVoter(uint256[2] publicKey) returns bool {

            require(msg.sender == ElectionAuthority, "Not authorized to do this");
            require(state == 1, "not in registration stage");
            required(Secp256k1.isPubKey(publickey), "Not a valid public key");
            required(registered[sha3(publicKey)] == false, "Voter already registered");

            if(ring[currentRingNo - 1].length == 2 * numVotersPerRing)
            {
                uint256 ringHash = LinkableRingSignature.hashToInt(ring[currentRingNo - 1]);
                hashRingtoNo[ringHash] = currentRingNo;
                currentRingNo+=1;
            }

            //push publickey to rings
            ring[currentRingNo-1].push(publicKey[0]);
            ring[currentRingNo-1].push(publicKey[1]);

            voters.push([publicKey[0],publicKey[1]]); //list of all voters, array of publickkey pairs

            registeredKeys[sha3(publicKey)] = true; //registered public key?
            hashKeytoRingNo[sha3(publicKey)] = currentRingNo; // publickey of voter to ringno

            return true;           


        }

        function gotoVotingPhase() returns bool{
            require(msg.sender == ElectionAuthority, "Not authorized to do this");
            require(state == 1, "Not in registration stage");

            if(ring[currentRingNo - 1].length <= 2 * numVotersPerRing)
            {
                uint256 ringHash = LinkableRingSignature.hashToInt(ring[currentRingNo - 1]);
                hashRingtoNo[ringHash] = currentRingNo;
                currentRingNo+=1;
            }

            state = 2;

            return true;
        }

        function submitVote(
            uint256[3] encryptedVote,
            
        )

    

}