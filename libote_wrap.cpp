#include "libote_wrap.h"
#include <libOTe/Base/BaseOT.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h>

#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <iostream>
#include <vector>
#include <string.h>

extern "C" {

const std::string IP = "localhost:1212";

void OTeSend(const uint16_t* messages1, const uint16_t* messages2, const int noOTs){
	using namespace osuCrypto;
	auto chl = cp::asioConnect(IP, 1);
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

	std::vector<std::array<block, 2>> sendMsgs(noOTs);
	//std::cout << "sent messages:" << std::endl;
	for(int i = 0; i < noOTs; i++){
		sendMsgs[i][0] = toBlock(messages1[i]);
		sendMsgs[i][1] = toBlock(messages2[i]);
		//std::cout << messages1[i] << std::endl;
		//std::cout << messages2[i] << std::endl;
	}
	try{
		cp::sync_wait(sender.sendChosen(sendMsgs, prng, chl));
	}
	catch(std::exception& e){
		std::cout << e.what() <<std::endl;
		cp::sync_wait(chl.close());
	}
	cp::sync_wait(chl.flush());	
}

void OTeRecv(uint8_t* retMsgs, const uint16_t* choices, const int noOTs){
	using namespace osuCrypto;
	auto chl = cp::asioConnect(IP, 0);
	PRNG prng(sysRandomSeed());
	IknpOtExtReceiver receiver;

	DefaultBaseOT base;
	std::vector<std::array<block, 2>> baseMsg(receiver.baseOtCount());
	try{
		cp::sync_wait(base.send(baseMsg, prng, chl));
	}
	catch(std::exception& e){
		std::cout << e.what() << std::endl;
		cp::sync_wait(chl.close());
	}
	receiver.setBaseOts(baseMsg);

	BitVector choice(noOTs);
	//std::cout << "choices:" << std::endl;
	for(int i = 0; i < noOTs; i++){
		choice[i] = choices[i] == 1;
		//std::cout << choices[i] << std::endl;
	}
	std::vector<block> recvMsgs(noOTs);
	try{
		cp::sync_wait(receiver.receiveChosen(choice, recvMsgs, prng, chl));
	}
	catch(std::exception& e){
		std::cout << e.what() << std::endl;
		cp::sync_wait(chl.close());
	}
	cp::sync_wait(chl.flush());
	//std::cout << "received messages:" << std::endl;
	for(auto i = 0; i < noOTs; i++){
		memcpy(retMsgs + i * 8, &recvMsgs[i], 8);
		//retMsgs[i] = recvMsgs[i];
	}
}
} // extern "C"

