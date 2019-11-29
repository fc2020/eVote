pragma solidity^0.5.0;
import './Crypto.sol';

contract eVote {
    address public admin;
    bool public validTally;
    Crypto crypto;
    mapping(address=> uint[2]) public publicKeys;
    mapping(address=> uint[2]) public votes;
    mapping(address=>bool) public refunded;
    address[] public voters;
    bytes32 public usersMerkleTreeRoot;
    bytes32 public computationMerkleTreeRoot;
    uint public finishRegistartionBlockNumber;
    uint public finishVotingBlockNumber;
    uint public finishTallyBlockNumber;
    uint public finishChallengeBlockNumber;
    uint public constant DEPOSIT = 1 ether;
    uint public voteResult;
    constructor(address _cryptoAddress, bytes32 _usersMerkleTreeRoot, uint _registrationBlockInterval, uint _votingBlockInterval,
     uint _tallyBlockInterval, uint _challengeBlockInterval) payable  public {
        require(msg.value==DEPOSIT,"Invalid deposit value");
        crypto = Crypto(_cryptoAddress);
        admin = msg.sender;
        usersMerkleTreeRoot = _usersMerkleTreeRoot;
        finishRegistartionBlockNumber = block.number+_registrationBlockInterval;
        finishVotingBlockNumber = finishRegistartionBlockNumber + _votingBlockInterval;
        finishTallyBlockNumber = finishVotingBlockNumber+_tallyBlockInterval;
        finishChallengeBlockNumber = finishTallyBlockNumber+_challengeBlockInterval;
    }
    function registerPublicKey(uint[2] memory _pubKey, uint[3] memory _discreteLogProof, bytes32[] memory _merkleProof) public payable{
        require(msg.value==DEPOSIT,"Invalid deposit value");
        require(block.number<finishRegistartionBlockNumber,"Registration phase is already closed");
        require(crypto.verifyMerkleProof(_merkleProof, usersMerkleTreeRoot, keccak256(abi.encodePacked(msg.sender))), "Invalid Merkle proof");
        require(crypto.verifyDL(_pubKey, _discreteLogProof),"Invalid DL proof");
        voters.push(msg.sender);
        publicKeys[msg.sender] = _pubKey;
    }
    function castVote(uint[2] memory _vote, uint[2] memory _Y, uint[7] memory _zeroOrOneProof) public {
        require(block.number >= finishRegistartionBlockNumber && block.number < finishVotingBlockNumber, "Voting phase is already closed");
        require(publicKeys[msg.sender] [0]!=0, "Unregistered voter");
        require(crypto.verifyZeroOrOne(_vote, _Y, _zeroOrOneProof),"Invalid zero or one proof");
        votes[msg.sender] = _vote;
    }
    function setTallyResult(uint _result, bytes32 _computationRoot, bytes32[] memory proof) public {
        require(msg.sender==admin,"Only admin can set the tally result");
        require(block.number >= finishVotingBlockNumber && block.number < finishTallyBlockNumber, "Tallying phase is already closed");
        uint[2] memory res = crypto.ecMul(_result);
        require(crypto.verifyMerkleProof(proof, _computationRoot, keccak256(abi.encodePacked(uint(0),res))),"Invalid result Merkle proof");
        validTally = true;
        voteResult = _result;
        computationMerkleTreeRoot = _computationRoot;
    }
    function disputeTallyResult(uint[3] memory ress,uint[3] memory op1,uint[3] memory op2, bytes32[] memory proof1,
     bytes32[] memory proof2,bytes32[] memory proof3 ) public {
        require(block.number >= finishTallyBlockNumber && block.number < finishChallengeBlockNumber, "Dispute phase is already closed");
        require(op1[0] == 2*ress[0]+1, "Invalid first operand index");
        require(op2[0] == 2*ress[0]+2, "Invalid second operand index");
        require(crypto.verifyMerkleProof(proof1, computationMerkleTreeRoot,
        keccak256(abi.encodePacked(ress))),"Invalid Merkle proof for the result");
        require(crypto.verifyMerkleProof(proof2, computationMerkleTreeRoot,
        keccak256(abi.encodePacked(op1))),"Invalid Merkle proof for the first operand");
        require(crypto.verifyMerkleProof(proof3, computationMerkleTreeRoot,
        keccak256(abi.encodePacked(op2))),"Invalid Merkle proof for the second operand");
        uint[2] memory temp = crypto.ecAdd([op1[1],op1[2]],[op2[1],op2[2]]);
        require(temp[0] != ress[1] || temp[1] != ress[2], "Invalid dispute, multiplication is already valid");
        validTally = false;
        voteResult = 0;
        msg.sender.transfer(DEPOSIT);
    }
    function disputeInput(uint[3] memory leaf, bytes32[] memory proof) public {
        require(block.number >= finishTallyBlockNumber && block.number < finishChallengeBlockNumber, "Dispute phase is already closed");
        require(crypto.verifyMerkleProof(proof, computationMerkleTreeRoot,
        keccak256(abi.encodePacked(leaf))),"Invalid Merkle proof for the input");
        uint circuitSize = voters.length * 2 - 1;
        uint index = circuitSize-1-leaf[0];
        if(index >= voters.length || crypto.Equal([leaf[1],leaf[2]],votes[voters[index]]) == false) {
            //invalid encoding or input
            validTally = false;
            voteResult = 0;
            msg.sender.transfer(DEPOSIT);
        }
    }
    function reclaimDeposit() public {
        require(block.number >= finishChallengeBlockNumber, "Invalid reclaim deposit phase");
        require(refunded[msg.sender] == false && (votes[msg.sender][0] != 0 || (validTally && msg.sender == admin) ),"Illegal reclaim");
        refunded[msg.sender] = true;
        msg.sender.transfer(DEPOSIT);
    }
}