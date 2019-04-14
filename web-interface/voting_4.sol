pragma solidity ^0.4.10;

import "./SECP256K1.sol";
import "./LinkableRingSignature.sol";

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

    int state;
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
    uint public n;

    //For threshold crypto

    uint256[2][] public secretShareVerifyPublicParams;
    mapping(uint256 => bool) public registeredSubSecrets;
    uint256[] public secretShare;
    uint256[2] public thresholdKey;
    uint256 public reconstructedKey = 0;

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

    function Voting() public {
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
        uint256[2] _thresholdKey) returns( bool) {
            require(state == 0 );
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

            for( i = 0 ; i < n ; i++)
            {
                secretShare.push(0);
            }

            secretShareVerifyPublicParams = _secretShareVerifyPublicParams;
            thresholdKey = _thresholdKey;
            state = 1;

            return true;


        }

        function registerVoter(uint256[2] publicKey) returns( bool) {

            require(msg.sender == ElectionAuthority, "Not authorized to do this");
            require(state == 1, "not in registration stage");
            require(Secp256k1.isPubKey(publicKey), "Not a valid public key");
            require(registeredKeys[sha3(publicKey)] == false, "Voter already registered");

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

        function gotoVotingPhase() returns (bool){
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

        function finishVoting() returns (bool) {
            require(msg.sender == ElectionAuthority, "Not authorized to do this");
            require(state == 2, "Not in voting stage");

            state = 3;
            return true;
        }

        function gotoTallyPhase() returns (bool) {
            require(msg.sender == ElectionAuthority, "Not authorized to do this");
            require(state == 3, "Not in Finished stage");
            require(secretShare.length == n,"number of parties dont match");

            for(uint i = 0; i < secretShare.length; i++) {
                require(secretShare[i]!=0,"zero secret");
            }

            require(reconstructedKey!=0,"key not set");

            state = 4;

            return true;
        }


        function submitVote(
            uint256[3] encryptedVote,
            uint256[] pubKeys,
            uint256 c_0,
            uint256[] sign,
            uint256[2] vlink)
        returns (bool){
            require(state == 2,"Not in voting phase");
            if(registeredVoteLink[sha3(vlink)] != 0) {
                return true;
            }

            uint256 Hashring = LinkableRingSignature.hashToInt(pubKeys);
            require(hashRingtoNo[Hashring]!=0,"hash not found");

            if(LinkableRingSignature.verifyRingSignature(uint256(sha3(encryptedVote)), pubKeys, c_0, sign, vlink)) {
                encryptedVotes.push([encryptedVote[0], encryptedVote[1], encryptedVote[2]]);
                registeredVoteLink[sha3(vlink)] = encryptedVotes.length;
                return true;
            }

            return false;

        }

        function publishSecretShares(uint index, uint256 subSecret) returns (bool){
            require(state==3,"Not in finished phase");
            require(!registeredSubSecrets[subSecret],"already registered");
            require(verifySecretShare(index, subSecret),"verifying secretshare failed");
            registeredSubSecrets[subSecret] = true;
            secretShare[index] = subSecret;
            return true;

        }

        function verifySecretShare(uint idx, uint256 subSecret) constant returns (bool){
            uint[2] memory Gs;
            Gs[0] = Gx;
            Gs[1] = Gy;

            uint256[2] memory verifyparams;
            verifyparams[0] = secretShareVerifyPublicParams[0][0];
            verifyparams[1] = secretShareVerifyPublicParams[0][1];

            for(uint j = 1; j < secretShareVerifyPublicParams.length; j++) {
                uint256[3] memory T = Secp256k1._addMixed(Secp256k1._mul( ((idx+1) ** j), secretShareVerifyPublicParams[j]), verifyparams);
                ECCMath.toZ1(T, pp);
                verifyparams[0] = T[0];
                verifyparams[1] = T[1];
            }

            uint256[3] memory R = Secp256k1._mul(subSecret, Gs);
            ECCMath.toZ1(R, pp);
            require(R[0] == verifyparams[0] && R[1] == verifyparams[1],"verification of secret share failed");
            return true;

        }

        function publish_reconstructedKey(uint256 rekey) returns (bool) {
            require(state==3,"not in finshed phase");
            require(reconstructedKey==0,"already published");
            uint[2] memory Gs;
            Gs[0] = Gx;
            Gs[1] = Gy;
            uint256[3] memory R = Secp256k1._mul(rekey, Gs);
            ECCMath.toZ1(R, pp);
            require(R[0] == thresholdKey[0] && R[1] == thresholdKey[1],"Publishing failed");
            reconstructedKey = rekey;
            state = 4;
            return true;

        }

        function tallyphase() constant returns (int[10]){
            require(state==4,"not in tally phase");
            int[10] memory electionResults;

            for(uint i = 0; i < encryptedVotes.length; i++){
                uint256[2] memory P;
                P[0] = encryptedVotes[i][0];
                P[1] = encryptedVotes[i][1];
                uint256 c = encryptedVotes[i][2];
                uint256[3] memory H = Secp256k1._mul(reconstructedKey, P);
                ECCMath.toZ1(H, pp);
                uint vote = mulmod(c, ECCMath.invmod(H[1], nn), nn);
                electionResults[vote] += 1;
            }

            return electionResults;
        }

        function getRingIdx(uint256[2] pubKey)constant returns (uint) {
            return hashKeytoRingNo[sha3(pubKey)];
        }


        function getRingSize(uint ringIdx) constant returns (uint) {
            return ring[ringIdx].length;
        }


        function getNumberCastedVotes() constant returns (uint) {
            return encryptedVotes.length;
        }


        function getNumRegisterVoters() constant returns (uint) {
            return voters.length;
        }


        function numOfSecrets() constant returns (uint) {
            return secretShare.length;
        }

}

