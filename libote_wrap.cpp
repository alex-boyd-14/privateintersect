#include "libote_wrap.h"
#include <libOTe/Base/SimplestOT.h>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h>
#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <iostream>
#include <vector>
#include <string.h>

extern "C"{

std::string sendIP = "10.0.4.211:1212";
std::string listenIP = "0.0.0.0:1212";

const int maxchunk = 4096;

int to_bytescpp(int no_bits){
    return std::ceil(no_bits / 8.0);
}

void OTeSend1(const uint8_t* messages1, const uint8_t* messages2, const int noOTs){
	using namespace osuCrypto;
	auto chl = cp::asioConnect(sendIP, 1);
	PRNG prng(sysRandomSeed());
	IknpOtExtSender sender;
    
	DefaultBaseOT base;
	BitVector bv(sender.baseOtCount());
	std::vector<block> baseMsg(sender.baseOtCount());
	bv.randomize(prng);

	try{
		cp::sync_wait(base.receive(bv, baseMsg, prng, chl));
	}
	catch(std::exception& e){
		std::cout << e.what() << std::endl;
		cp::sync_wait(chl.close());
	}
	sender.setBaseOts(baseMsg, bv);

    int totalchunks = std::ceil((double)noOTs / maxchunk);
    int remainder = noOTs % maxchunk;
    
    for(int chunk = 0; chunk < totalchunks; chunk++){
        bool finalchunk = chunk + 1 == totalchunks;
        int chunklen = !finalchunk || (finalchunk && !remainder)? maxchunk: noOTs % maxchunk;
        int checkpoint = to_bytescpp(chunk * maxchunk);
        std::vector<std::array<block, 2>> sendMsgs(chunklen);
        int j = 0, k = 0;
        for(int i = 0; i < chunklen; i++){
            if(k == 8){
                k = 0;
                j++;
            }
            sendMsgs[i][0] = toBlock(messages1[checkpoint + j] >> k & 1);
            sendMsgs[i][1] = toBlock(messages2[checkpoint + j] >> k++ & 1);
        }
        try{
            cp::sync_wait(sender.sendChosen(sendMsgs, prng, chl));
        }
        catch(std::exception& e){
            std::cout << e.what() << std::endl;
            cp::sync_wait(chl.close());
        }
        cp::sync_wait(chl.flush());
    }
}

void OTeSend32(const uint32_t* messages1, const uint32_t* messages2, const int noOTs){
    using namespace osuCrypto;
    auto chl = cp::asioConnect(sendIP, 1);
    PRNG prng(sysRandomSeed());
    IknpOtExtSender sender;

    DefaultBaseOT base;
    BitVector bv(sender.baseOtCount());
    std::vector<block> baseMsg(sender.baseOtCount());
    bv.randomize(prng);

    try{
        cp::sync_wait(base.receive(bv, baseMsg, prng, chl));
    }
    catch(std::exception& e){
        std::cout << e.what() << std::endl;
        cp::sync_wait(chl.close());
    }
    sender.setBaseOts(baseMsg, bv);

    int totalchunks = std::ceil((double)noOTs / maxchunk);
    int remainder = noOTs % maxchunk;
    
    for(int chunk = 0; chunk < totalchunks; chunk++){
        bool finalchunk = chunk + 1 == totalchunks;
        int chunklen = !finalchunk || (finalchunk && !remainder)? maxchunk: noOTs % maxchunk;
        int checkpoint = chunk * maxchunk;
        std::vector<std::array<block, 2>> sendMsgs(chunklen);
        for(int i = 0; i < chunklen; i++){
            sendMsgs[i][0] = toBlock(messages1[checkpoint + i]);
            //std::cout << (int)(messages1[checkpoint + j] >> k & 1) << std::endl;
            sendMsgs[i][1] = toBlock(messages2[checkpoint + i]);
        }
        try{
            cp::sync_wait(sender.sendChosen(sendMsgs, prng, chl));
        }
        catch(std::exception& e){
            std::cout << e.what() << std::endl;
            cp::sync_wait(chl.close());
        }
        cp::sync_wait(chl.flush());
    }
}

void OTeRecv1(uint8_t* retMsgs, const uint8_t* choices, const int noOTs){
	using namespace osuCrypto;
	auto chl = cp::asioConnect(listenIP, 0);
	PRNG prng(sysRandomSeed());
	IknpOtExtReceiver receiver;

	DefaultBaseOT base;
	std::vector<std::array<block, 2>> baseMsg(receiver.baseOtCount());
    //std::cout << receiver.baseOtCount() << std::endl;
	try{
		cp::sync_wait(base.send(baseMsg, prng, chl));
	}
	catch(std::exception& e){
		std::cout << e.what() << std::endl;
		cp::sync_wait(chl.close());
	}
	receiver.setBaseOts(baseMsg);
    
    int totalchunks = std::ceil((double)noOTs / maxchunk);
    int remainder = noOTs % maxchunk;
    
    for(int chunk = 0; chunk < totalchunks; chunk++){
        bool finalchunk = chunk + 1 == totalchunks;
        int chunklen = !finalchunk || (finalchunk && !remainder)? maxchunk: noOTs % maxchunk;
        int checkpoint = to_bytescpp(chunk * maxchunk);
        //std::cout << chunk << std::endl;
        BitVector choice(chunklen);
        int j = 0, k = 0;
        for(int i = 0; i < chunklen; i++){
            if(k == 8){
                k = 0;
                j++;
            }
            choice[i] = (choices[checkpoint + j] >> k++) & 1;
        }
        std::vector<block> recvMsgs(chunklen);
        try{
            cp::sync_wait(receiver.receiveChosen(choice, recvMsgs, prng, chl));
        }
        catch(std::exception& e){
            std::cout << e.what() << std::endl;
            cp::sync_wait(chl.close());
        }
        cp::sync_wait(chl.flush());
        j = 0, k = 0;
        uint8_t temp, acc = 0;
        for(int i = 0; i < chunklen; i++){
            memcpy(&temp, &recvMsgs[i], 1);
            acc += temp << k++;
            if(k == 8){
                //std::cout << (int)acc << std::endl;
                //std::cout << (checkpoint + j) << std::endl;
                retMsgs[checkpoint + j] = acc;
                acc = 0;
                k = 0;
                j++;
            }
        }
        if(k != 0){
            retMsgs[checkpoint + j] = acc;
            //std::cout << (checkpoint) << std::endl;
        }
    }
}

void OTeRecv32(uint32_t* retMsgs, const uint8_t* choices, const int noOTs){
    using namespace osuCrypto;
    auto chl = cp::asioConnect(listenIP, 0);
    PRNG prng(sysRandomSeed());
    IknpOtExtReceiver receiver;

    DefaultBaseOT base;
    std::vector<std::array<block, 2>> baseMsg(receiver.baseOtCount());
    //std::cout << receiver.baseOtCount() << std::endl;
    try{
        cp::sync_wait(base.send(baseMsg, prng, chl));
    }
    catch(std::exception& e){
        std::cout << e.what() << std::endl;
        cp::sync_wait(chl.close());
    }
    receiver.setBaseOts(baseMsg);

    int totalchunks = std::ceil((double)noOTs / maxchunk);
    int remainder = noOTs % maxchunk;
    
    for(int chunk = 0; chunk < totalchunks; chunk++){
        bool finalchunk = chunk + 1 == totalchunks;
        int chunklen = !finalchunk || (finalchunk && !remainder)? maxchunk: noOTs % maxchunk;
        int checkpoint = chunk * maxchunk;
        //std::cout << chunk << std::endl;
        BitVector choice(chunklen);
        int j = 0, k = 0;
        for(int i = 0; i < chunklen; i++){
            if(k == 8){
                k = 0;
                j++;
            }
            choice[i] = (choices[to_bytescpp(checkpoint) + j] >> k++) & 1;
        }
        std::vector<block> recvMsgs(chunklen);
        try{
            cp::sync_wait(receiver.receiveChosen(choice, recvMsgs, prng, chl));
        }
        catch(std::exception& e){
            std::cout << e.what() << std::endl;
            cp::sync_wait(chl.close());
        }
        cp::sync_wait(chl.flush());
        for(int i = 0; i < chunklen; i++)
            memcpy(retMsgs + checkpoint + i, &recvMsgs[i], 4);
    }
}
}

