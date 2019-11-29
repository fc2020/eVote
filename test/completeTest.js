const Web3 = require('web3')
const web3 = new Web3(new Web3.providers.HttpProvider('http://localhost:8545'));
const assert = require('assert')
const eVote = artifacts.require("eVote.sol")
const Crypto = artifacts.require("Crypto.sol")
const { MerkleTree } = require('../helper/merkletree.js')
const {mineToBlockNumber, takeSnapshot,revertToSnapshot} = require('../helper/truffleHelper.js')
const { keccak256} = require('ethereumjs-util')
const random = require('crypto');  
const abi = require('ethereumjs-abi')

contract('eVote', async (accounts) => {
    let voters = [], admin = accounts[0]
    let usersMerkleTree = new MerkleTree(accounts.slice(1,accounts.length-1))    
    let cryptoInstance, eVoteInstance
    it('Deploy the contracts', async ()=> {
        cryptoInstance = await Crypto.deployed()
        eVoteInstance = await eVote.deployed()
    })

    
    it('Register public keys for elligable users', async() => {
        for(let i =1; i< accounts.length-1; i++) {
            _x = random.randomBytes(256)
            _a = random.randomBytes(256) 
            _xG = await cryptoInstance.ecMul(_x)
            _merkleProof = usersMerkleTree.getHexProof(accounts[i])
            _discreteLogProof= await cryptoInstance.proveDL(_xG,_x,_a)            
            await eVoteInstance.registerPublicKey(_xG, _discreteLogProof, _merkleProof, {from:accounts[i], value:web3.utils.toWei("1","ether")})
            voters.push( {address:accounts[i], x: _x, xG: _xG, vote: Math.floor(Math.random()*2), Y: null, xY: null, xYvG:null})               
        }
    })    

    it('Throw an error if non-elligable user tries to vote', async() =>{
        snapShot = await takeSnapshot()
        snapshotId = snapShot['result']
        _x = random.randomBytes(256)
        _a = random.randomBytes(256) 
        _xG = await cryptoInstance.ecMul(_x)
        _merkleProof = usersMerkleTree.getHexProof(accounts[accounts.length-2])
        _discreteLogProof= await cryptoInstance.proveDL(_xG,_x,_a)            
        try{
        await eVoteInstance.registerPublicKey(_xG, _discreteLogProof, _merkleProof, {from:accounts[accounts.length-1], value:web3.utils.toWei("1","ether")})
        }
        catch(err) {
            assert(String(err).includes("Invalid Merkle proof"), "error in verifying invalid user")
        }
        await revertToSnapshot(snapshotId)
        
    })

    it('Throw an error if elligable user provides invalid DL proof to vote', async() =>{
        snapShot = await takeSnapshot()
        snapshotId = snapShot['result']
        _x = random.randomBytes(256)
        _y = random.randomBytes(256)
        _a = random.randomBytes(256) 
        _xG = await cryptoInstance.ecMul(_x)
        _merkleProof = usersMerkleTree.getHexProof(accounts[accounts.length-2])
        _discreteLogProof= await cryptoInstance.proveDL(_xG,_y,_a)            
        try{
        await eVoteInstance.registerPublicKey(_xG, _discreteLogProof, _merkleProof, {from:accounts[accounts.length-2], value:web3.utils.toWei("1","ether")})
        }
        catch(err) {
            assert(String(err).includes("Invalid DL proof"), "error in verifying invalid user")
        }
        await revertToSnapshot(snapshotId)
    })

    it('Cast valid votes', async() => {
        beginVote = (await eVoteInstance.finishRegistartionBlockNumber.call()).toNumber()
        await mineToBlockNumber(beginVote)
        for(let i=0; i<voters.length; i++)
        {
            num = await cryptoInstance.ecMul(0)
            den = await cryptoInstance.ecMul(0)
            for(let j=0; j<i; j++) 
                num = await cryptoInstance.ecAdd(num, voters[j].xG)            
            for(let k=i+1; k<voters.length;k++) 
                den = await cryptoInstance.ecAdd(den,voters[k].xG)
            voters[i].Y = await cryptoInstance.ecSub(num,den)
            voters[i].xY = await cryptoInstance.ecMul(voters[i].x, voters[i].Y)
            temp = await cryptoInstance.ecMul(voters[i].vote)
            voters[i].xYvG = await cryptoInstance.ecAdd(voters[i].xY,temp)
            a = random.randomBytes(256)
            s = random.randomBytes(256)
            t = random.randomBytes(256)
            proof = await cryptoInstance.proveZeroOrOne(voters[i].xYvG,voters[i].Y,voters[i].vote,voters[i].x,a,s,t);
            await eVoteInstance.castVote(voters[i].xYvG, voters[i].Y, proof, {from:voters[i].address})
        }        
    })

    it('Dispute on invalid computation result', async() => {
        computationArray = []

        snapShot = await takeSnapshot();
        snapshotId = snapShot['result'];

        beginTally = (await eVoteInstance.finishVotingBlockNumber.call()).toNumber()
        await mineToBlockNumber(beginTally)
        let result = await cryptoInstance.ecMul(0)
        let tempComputationArray =[]

        //compute the tally and add inputs to the circuit
        for(let i =0; i<voters.length;i++) {
            result = await cryptoInstance.ecAdd(result, voters[i].xYvG)
            tempComputationArray.push(voters[i].xYvG)
        }
 
        //brute force the DL
        let vote =-1 
        for(let i=0;i<voters.length;i++) {
            temp = await cryptoInstance.ecMul(i)
            if(temp[0].eq(result[0]) && temp[1].eq(result[1])) {
                vote = i
                break
            }
        }        

        assert(vote>=0,"Couldn't brute-force the vote result")

        //create computation circuit
        for(let i=0; i<tempComputationArray.length-1; i+=2 )
            tempComputationArray.push(await cryptoInstance.ecAdd(tempComputationArray[i],tempComputationArray[i+1]))
        
        tempComputationArray = tempComputationArray.reverse()

        //Maliciously introduce extra vote in the tally
        one = await cryptoInstance.ecMul(1)
        tempComputationArray[0] = await cryptoInstance.ecAdd(tempComputationArray[0], one)
        vote +=1
        

        //encode the computation circuit and accumulate it by a Merkle tree
        for(let i=0; i<tempComputationArray.length;i++) {
            data = [i, tempComputationArray[i][0],tempComputationArray[i][1]]
            computationArray.push(abi.rawEncode(['uint[3]'],[data]))
        }
        
        computationMerkleTree = new MerkleTree(computationArray);        
        await eVoteInstance.setTallyResult(vote, computationMerkleTree.getHexRoot(), computationMerkleTree.getHexProof(computationArray[0]),{from:admin})

        //advance to dispute interval 
        beginDispute = (await eVoteInstance.finishTallyBlockNumber.call()).toNumber()
        await mineToBlockNumber(beginDispute)

        //dispute the final result != op1*op2
        proof1 = computationMerkleTree.getHexProof(computationArray[0])
        proof2 = computationMerkleTree.getHexProof(computationArray[1])
        proof3 = computationMerkleTree.getHexProof(computationArray[2])               

        res = abi.rawDecode(['uint[3]'],computationArray[0])[0]
        op1 = abi.rawDecode(['uint[3]'],computationArray[1])[0]
        op2 = abi.rawDecode(['uint[3]'],computationArray[2])[0]
        
        //user reports the error that the final result isn't the multiplication of its two operands (we maliciously added extra one)
        await eVoteInstance.disputeTallyResult(res, op1, op2, proof1,proof2,proof3,{from:voters[0].address})
        validTally = await eVoteInstance.validTally.call()
        assert(validTally==false,"Failed to dispute on error")  

        await revertToSnapshot(snapshotId)        
    })
    
    it('Dispute on invalid vote input', async() => {
        computationArray = []
        snapShot = await takeSnapshot();
        snapshotId = snapShot['result'];

        beginTally = (await eVoteInstance.finishVotingBlockNumber.call()).toNumber()
        await mineToBlockNumber(beginTally)

        let tempComputationArray =[]
        //maliciously change first input by adding extra one vote to it
        tempComputationArray.push(await cryptoInstance.ecAdd(voters[0].xYvG, await cryptoInstance.ecMul(1)))
        result = tempComputationArray[0]

        //compute the tally and add inputs to the circuit
        for(let i =1; i<voters.length;i++) {
            result = await cryptoInstance.ecAdd(result, voters[i].xYvG)
            tempComputationArray.push(voters[i].xYvG)
        }             
 
        //brute force the DL
        vote =-1 
        for(let i=0;i<voters.length;i++) {
            temp = await cryptoInstance.ecMul(i)
            if(temp[0].eq(result[0]) && temp[1].eq(result[1])) {
                vote = i
                break
            }
        }

        assert(vote>=0,"Couldn't brute-force the vote result")

        //create computation circuit
        for(let i=0; i<tempComputationArray.length-1; i+=2 )
            tempComputationArray.push(await cryptoInstance.ecAdd(tempComputationArray[i],tempComputationArray[i+1]))
        
        tempComputationArray = tempComputationArray.reverse()

        //encode the computation circuit and accumulate it by a Merkle tree
        for(let i=0; i<tempComputationArray.length;i++) {
            data = [i, tempComputationArray[i][0],tempComputationArray[i][1]]
            computationArray.push(abi.rawEncode(['uint[3]'],[data]))
        }
                
        computationMerkleTree = new MerkleTree(computationArray);        
        await eVoteInstance.setTallyResult(vote, computationMerkleTree.getHexRoot(), computationMerkleTree.getHexProof(computationArray[0]), {from:admin})

        //advance to dispute interval 
        beginDispute = (await eVoteInstance.finishTallyBlockNumber.call()).toNumber()
        await mineToBlockNumber(beginDispute)

        //dispute the first input in the tree != first voter's input result != op1*op2
        index = computationArray.length-1
        proof = computationMerkleTree.getHexProof(computationArray[index])
        input = abi.rawDecode(['uint[3]'],computationArray[index])[0]        
            
        await eVoteInstance.disputeInput(input, proof,{from:voters[0].address})
        validTally = await eVoteInstance.validTally.call()
        assert(validTally==false,"Failed to dispute on error")  

        await revertToSnapshot(snapshotId)
    })

    it('Throw an error on disputing valid tally', async() => {
        computationArray = []
        beginTally = (await eVoteInstance.finishVotingBlockNumber.call()).toNumber()
        await mineToBlockNumber(beginTally)
        let result = await cryptoInstance.ecMul(0)
        let tempComputationArray =[]

        //compute the tally and add inputs to the circuit
        for(let i =0; i<voters.length;i++) {
            result = await cryptoInstance.ecAdd(result, voters[i].xYvG)
            tempComputationArray.push(voters[i].xYvG)
        }

        //brute force the DL
        let vote =-1 
        for(let i=0;i<voters.length;i++) {
            temp = await cryptoInstance.ecMul(i)
            if(temp[0].eq(result[0]) && temp[1].eq(result[1])) {
                vote = i
                break
            }
        }
        assert(vote>=0,"Couldn't brute-force the vote result")

        //create computation circuit
        for(let i=0; i<tempComputationArray.length-1; i+=2 )
            tempComputationArray.push(await cryptoInstance.ecAdd(tempComputationArray[i],tempComputationArray[i+1]))
        tempComputationArray = tempComputationArray.reverse()

        //encode the computation circuit and accumulate it by a Merkle tree
        for(let i=0; i<tempComputationArray.length;i++) {
            data = [i, tempComputationArray[i][0],tempComputationArray[i][1]]
            computationArray.push(abi.rawEncode(['uint[3]'],[data]))
        }
                
        computationMerkleTree = new MerkleTree(computationArray);        
        await eVoteInstance.setTallyResult(vote, computationMerkleTree.getHexRoot(), computationMerkleTree.getHexProof(computationArray[0]), {from:admin})

        snapShot = await takeSnapshot();
        snapshotId = snapShot['result'];

        //advance to dispute interval 
        beginDispute = (await eVoteInstance.finishTallyBlockNumber.call()).toNumber()
        await mineToBlockNumber(beginDispute)

        //dispute the final result != op1*op2
        proof1 = computationMerkleTree.getHexProof(computationArray[0])
        proof2 = computationMerkleTree.getHexProof(computationArray[1])
        proof3 = computationMerkleTree.getHexProof(computationArray[2])               

        res = abi.rawDecode(['uint[3]'],computationArray[0])[0]
        op1 = abi.rawDecode(['uint[3]'],computationArray[1])[0]
        op2 = abi.rawDecode(['uint[3]'],computationArray[2])[0]
        
        //should revert as the multiplication is correct
        try {
        await eVoteInstance.disputeTallyResult(res, op1, op2, proof1,proof2,proof3,{from:voters[0].address})
        }catch(err) {
            assert(String(err).includes('Invalid dispute, multiplication is already valid'),'Fail to verify valid multiplication')
        }
        await revertToSnapshot(snapshotId)
    })

    it('Refund deposits for all', async () => {
        beginRefund = (await eVoteInstance.finishChallengeBlockNumber.call()).toNumber()
        await mineToBlockNumber(beginRefund)

        for(let i =0; i< accounts.length-1; i++) {
            await eVoteInstance.reclaimDeposit({from:accounts[i]})
        }
    })
})
