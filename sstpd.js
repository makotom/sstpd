(function () {
	"use strict";

	var tls = require("tls"), fs = require("fs"), crypto = require("crypto"), child_process = require("child_process"),

	CONFIG = {
		serverAddr : ["0.0.0.0", "::"],
		port : 43443,
		keyPEM : "key.pem",
		certPEM : "cert.pem",
		serverV4 : "10.15.0.1",
		clientIPv4Range : ["10.15.254.1", "10.15.254.255"],
	},

	CONST = (function () {
		var ret = {};

		ret.key = fs.readFileSync(CONFIG.keyPEM);
		ret.cert = fs.readFileSync(CONFIG.certPEM);
		ret.certHash = (function (pemBuffer) {
			var pemString = pemBuffer.toString(),
			certBase64 = pemString.replace(/-----(?:BEGIN|END) CERTIFICATE-----\n/g, "").replace(/\n/g, ""),
			cert = new Buffer(certBase64, "base64");

			return crypto.createHash("sha256").update(cert).digest();
		})(ret.cert);
		ret.TLSCiphers = "AESGCM:CAMELLIA256";
		ret.CRCode = "\r".charCodeAt();
		ret.LFCode = "\n".charCodeAt();
		ret.serverVersion = 0x10;
		ret.prodName = "sstpd/devel";

		return ret;
	})(),

	IPv4Pool = (function (v4Range) {
		var ret = {},
		v4FromPartsStr = v4Range[0].split("."), v4ToPartsStr = v4Range[1].split("."),
		v4FromParts = [parseInt(v4FromPartsStr[0], 10), parseInt(v4FromPartsStr[1], 10), parseInt(v4FromPartsStr[2], 10), parseInt(v4FromPartsStr[3])],
		v4ToParts = [parseInt(v4ToPartsStr[0], 10), parseInt(v4ToPartsStr[1], 10), parseInt(v4ToPartsStr[2], 10), parseInt(v4ToPartsStr[3])],
		counter = null;

		if (
			! isNaN(v4FromParts[0]) && ! isNaN(v4FromParts[1]) && ! isNaN(v4FromParts[2]) && ! isNaN(v4FromParts[3]) &&
			! isNaN(v4ToParts[0]) && ! isNaN(v4ToParts[1]) && ! isNaN(v4ToParts[2]) && ! isNaN(v4ToParts[3])
		) {
			counter = v4FromParts.slice();
			for (; counter[0] <= v4ToParts[0]; counter[0] += 1) {
				for (; counter[1] <= v4ToParts[1]; counter[1] += 1) {
					for (; counter[2] <= v4ToParts[2]; counter[2] += 1) {
						for (; counter[3] <= v4ToParts[3]; counter[3] += 1) {
							ret[counter.join(".")] = false;
						}
						counter[3] = 1;
					}
					counter[2] = 0;
				}
				counter[1] = 0;
			}
		}

		return ret;
	})(CONFIG.clientIPv4Range),

	chooseFreeIPv4 = function () {
		for (let addr in IPv4Pool) {
			if (IPv4Pool.hasOwnProperty(addr) && ! IPv4Pool[addr]) {
				IPv4Pool[addr] = true;
				return addr;
			}
		}

		return "0.0.0.0";
	},

	SSTPPeer = function (stream) {
		this.serverVersion = CONST.serverVersion;
		this.serverCertificateHash = CONST.certHash;
		this.serverHashProtocolSupported = 2;
		this.nonce = crypto.pseudoRandomBytes(32);
		this.IPv4Addr = chooseFreeIPv4();

		this.stream = stream;
		this.pppd = null;
		this.sstpFifo = [];
		this.pppLastOctetIsEscape = false;
		this.pppProcessingLargeFrame = false;

		this.currentState = this.knownStates.STANDBY;
		this.requestHeader = null;
		this.timers = {};

		this.stream.on("data", this.inputParser.bind(this));
		this.stream.on("close", this.closePeer.bind(this));
		this.stream.on("error", function (e) { console.log(e.stack); });
	};

	SSTPPeer.prototype.knownStates = (function () {
		var ret = {};

		[
			"STANDBY",
			"HTTPS_REJECTED",
			"HTTPS_OPENED",
			"SERVER_CONNECT_REQUEST_PENDING",
			"SERVER_CALL_CONNECTED_PENDING",
			"SERVER_CALL_CONNECTED",
			"SERVER_CALL_DISCONNECTED",
			"CALL_ABORT_IN_PROGRESS_1",
			"CALL_ABORT_IN_PROGRESS_2",
			"CALL_ABORT_TIMEOUT_PENDING",
			"CALL_ABORT_PENDING",
			"CALL_DISCONNECT_IN_PROGRESS_1",
			"CALL_DISCONNECT_IN_PROGRESS_2",
			"CALL_DISCONNECT_ACK_PENDING",
			"CALL_DISCONNECT_TIMEOUT_PENDING",
		].forEach(function (state, id) {
			ret[state] = id;
		});

		return ret;
	})();

	SSTPPeer.prototype.parseHTTPHeaderInSSTPFifo = function () {
		var chunk = null, line = [];

		while (chunk = this.sstpFifo.shift()) {
			let p = 0;

			for (p = 0; p < chunk.length; p += 1) {
				if (chunk[p] === CONST.CRCode || chunk[p] === CONST.LFCode) {
					if ((chunk[p] === CONST.CRCode && chunk[p + 1] === CONST.LFCode) || (chunk[p] === CONST.LFCode && chunk[p + 1] === CONST.CRCode)) {
						p += 1;
					}

					if (line.length === 0) {
						p += 1;
						this.currentState = this.knownStates.HTTPS_OPENED;
						break;
					}

					if (this.requestHeader === null) {
						let requestLine = new Buffer(line).toString().split(" ");

						if (requestLine.length !== 3) {
							this.currentState = this.knownStates.HTTPS_REJECTED;
							return null;
						}

						this.requestHeader = {
							requestLine : {
								method : requestLine[0],
								URI : requestLine[1],
								version : requestLine[2]
							}
						};
					} else {
						let messageHeader = new Buffer(line).toString().split(":");

						if (messageHeader.length < 2) {
							this.currentState = this.knownStates.HTTPS_REJECTED;
							return null;
						}

						this.requestHeader[messageHeader.shift()] = messageHeader.join(":").replace(/^\s*/, "");
					}

					line = [];
					continue;
				}

				line.push(chunk[p]);
			}

			if (this.currentState === this.knownStates.HTTPS_OPENED) {
				if (p < chunk.length) {
					this.sstpFifo.unshift(chunk.slice(p));
				}

				return this.requestHeader;
			}
		}

		if (line.length > 0) {
			this.sstpFifo.unshift(new Buffer(line));
			return null;
		}
	};

	SSTPPeer.prototype.isAcceptableHTTPSRequest = function () {
		return true;
	};

	SSTPPeer.prototype.readBytesFromSSTPFifo = function (bytes) {
		var ret = [],
		chunk = null, p = 0;

		if (this.sstpFifo.length < 1) {
			return null;
		}

		while (ret.length < bytes && this.sstpFifo.length > 0) {
			chunk = this.sstpFifo.shift();

			for (p = 0; ret.length < bytes && p < chunk.length; p += 1) {
				ret.push(chunk[p]);
			}
		}

		if (p < chunk.length) {
			this.sstpFifo.unshift(chunk.slice(p));
		}

		if (ret.length < bytes) {
			this.sstpFifo.unshift(new Buffer(ret));
			return null;
		}

		return ret;
	};

	SSTPPeer.prototype.fetchSSTPMsgFromFIFO = function () {
		var ret = {},
		headerBytes = null, dataBytes = null;

		{
			headerBytes = this.readBytesFromSSTPFifo(4);

			if (headerBytes === null) {
				return null;
			}

			ret.version = headerBytes[0];
			ret.isControl = headerBytes[1] % 2 === 1;
			ret.length = 256 * (headerBytes[2] % 16) + headerBytes[3];
		}

		{
			dataBytes = this.readBytesFromSSTPFifo(ret.length - headerBytes.length);

			if (dataBytes === null) {
				this.sstpFifo.unshift(new Buffer(headerBytes));
				return null;
			}

			ret.data = new Buffer(dataBytes);
		}

		delete ret.length;

		return ret;
	};

	SSTPPeer.prototype.parseSSTPCtrlMsgAttrVal = function (attrId, attrVal) {
		switch (attrId) {
			case 0x01:
				return attrVal.readUInt16BE(0);

			case 0x02:
				{
					let ret = {};

					ret.attribID = attrVal.readUInt8(3);
					ret.status = attrVal.readUInt32BE(4);

					return ret;
				}

			case 0x03:
				{
					let ret = {};

					ret.hashProtocol = attrVal.readUInt8(3);
					ret.nonce = attrVal.slice(4, 36);

					if (ret.hashProtocol === 1) {
						ret.certHash = attrVal.slice(36, 56);
						ret.CMAC = attrVal.slice(68, 88);
					} else if (ret.hashProtocol === 2) {
						ret.certHash = attrVal.slice(36, 68);
						ret.CMAC = attrVal.slice(68, 100);
					} else {
						return null;
					}

					return ret;
				}

			case 0x04:
				return {
					hashProtocol : attrVal.readUInt8(3),
					nonce : attrVal.slice(4, 36)
				};
		}
	};

	SSTPPeer.prototype.validateSSTPControlMessage = function (cMsg) {
		switch (cMsg.messageType) {
			case 0x0001:
				return cMsg.attributes.length === 1 && cMsg.attributes[0].id === 0x01 && cMsg.attributes[0].value === 0x0001;
			case 0x0002:
				return cMsg.attributes.length === 1 && cMsg.attributes[0].id === 0x04 && cMsg.attributes[0].value.hashProtocol > 0 && cMsg.attributes[0].value.hashProtocol < 4;
			case 0x0003:
				return cMsg.attributes.length === 1 && cMsg.attributes[0].id === 0x02;
			case 0x0004:
				return cMsg.attributes.length === 1 && cMsg.attributes[0].id === 0x03;
			case 0x0005:
				return cMsg.attributes.length === 0 || (cMsg.attributes.length === 1 && cMsg.attributes[0].id === 0x02);
			case 0x0006:
				return cMsg.attributes.length === 0 || (cMsg.attributes.length === 1 && cMsg.attributes[0].id === 0x02 && cMsg.attributes[0].value.attribID === 0x0 && cMsg.attributes[0].value.status === 0x0);
			case 0x0007:
			case 0x0008:
			case 0x0009:
				return cMsg.attributes.length === 0;
			default:
				return false;
		}
	};

	SSTPPeer.prototype.parseSSTPControlMessage = function (msg) {
		var ret = {};

		try {
			ret.version = msg.version;
			ret.messageType = msg.data.readUInt16BE(0);
			ret.numAttributes = msg.data.readUInt16BE(2);
			ret.attributes = [];

			for (let i = 0, p = 4; i < ret.numAttributes; i += 1) {
				let attr = {};

				attr.id = msg.data[p += 1];
				attr.length = 256 * (msg.data[p += 1] % 16) + msg.data[p += 1];
				attr.value = this.parseSSTPCtrlMsgAttrVal(attr.id, msg.data.slice(p += 1, p += attr.length - 4));

				delete attr.length;

				ret.attributes.push(attr);
			}

			delete ret.numAttributes;
		} catch (e) {
			console.log(e.stack);
			return null;
		}

		ret.isValidMessage = this.validateSSTPControlMessage(ret);

		return ret;
	};

	SSTPPeer.prototype.genSSTPCtrlMsg = function (messageType, attributes) {
		var msgParts = null, msgHeader = new Buffer(8), packetLength = 0;

		attributes.forEach(function (attribute) {
			packetLength += attribute.length;
		});
		packetLength += 8;

		msgHeader[0] = this.serverVersion;
		msgHeader[1] = 0x1;
		msgHeader.writeUInt16BE(packetLength, 2);
		msgHeader.writeUInt16BE(messageType, 4);
		msgHeader.writeUInt16BE(attributes.length, 6);

		msgParts = attributes.slice();
		msgParts.unshift(msgHeader);

		return Buffer.concat(msgParts, packetLength);
	};

	SSTPPeer.prototype.genSSTPCtrlMsgAttr = function (attrId, data) {
		var attrHeader= new Buffer(4);

		attrHeader[0] = 0x00;
		attrHeader[1] = attrId;
		attrHeader.writeUInt16BE(4 + data.length, 2);

		return Buffer.concat([attrHeader, data], attrHeader.length + data.length);
	};

	SSTPPeer.prototype.genCompoundMAC = function (K) {
		var cmac = new Buffer(32),
		S = new Buffer("SSTP inner method derived CMK"), LEN = new Buffer([32, 0]),
		hmac = null, CMK = null, sstpCallConnectedMsg = null;

		cmac.fill(0);
		sstpCallConnectedMsg = this.genSSTPCtrlMsg(0x0004, [this.genSSTPCtrlMsgAttr(0x03, Buffer.concat([new Buffer([0x00, 0x00, 0x00, this.serverHashProtocolSupported]), this.nonce, this.serverCertificateHash, cmac]))]);

		hmac = crypto.createHmac("sha256", K);
		hmac.update(S);
		hmac.update(LEN);
		hmac.update(new Buffer([0x01]));
		CMK = hmac.digest();

		hmac = crypto.createHmac("sha256", CMK);
		hmac.update(sstpCallConnectedMsg);

		return hmac.digest();
	};

	SSTPPeer.prototype.sendCallConnectACK = function () {
		this.stream.write(this.genSSTPCtrlMsg(0x0002, [this.genSSTPCtrlMsgAttr(0x04, Buffer.concat([new Buffer([0x00, 0x00, 0x00, this.serverHashProtocolSupported]), this.nonce], 4 + this.nonce.length))]));
	};

	SSTPPeer.prototype.sendCallConnectNAK = function () {
		// NOTE: Sending custom status message
		this.stream.write(this.genSSTPCtrlMsg(0x0003, [this.genSSTPCtrlMsgAttr(0x02, new Buffer([0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff]))]));
	};

	SSTPPeer.prototype.sendCallAbort = function () {
		// NOTE: Sending custom status message
		this.stream.write(this.genSSTPCtrlMsg(0x0005, [this.genSSTPCtrlMsgAttr(0x02, new Buffer([0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff]))]));
	};

	SSTPPeer.prototype.sendCallDisconnect = function () {
		this.stream.write(this.genSSTPCtrlMsg(0x0006, [this.genSSTPCtrlMsgAttr(0x02, new Buffer([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))]));
	};

	SSTPPeer.prototype.sendCallDisconnectACK = function () {
		this.stream.write(this.genSSTPCtrlMsg(0x0007, []));
	};

	SSTPPeer.prototype.sendEchoRequest = function () {
		this.stream.write(this.genSSTPCtrlMsg(0x0008, []));
	};

	SSTPPeer.prototype.sendEchoResponse = function () {
		this.stream.write(this.genSSTPCtrlMsg(0x0009, []));
	};

	SSTPPeer.prototype.setNegotiationTimer = function () {
		this.timers.negotiationTimer = setTimeout(this.abortCall.bind(this), 60 * 1000);
	};

	SSTPPeer.prototype.setAbortStateTimer1 = function () {
		this.timers.abortStateTimer1 = setTimeout(this.disconnectPeer.bind(this), 3 * 1000);
	};

	SSTPPeer.prototype.setAbortStateTimer2 = function () {
		this.timers.abortStateTimer2 = setTimeout(this.disconnectPeer.bind(this), 1 * 1000);
	};

	SSTPPeer.prototype.setDisconnectStateTimer1 = function () {
		this.timers.disconnectStateTimer1 = setTimeout(this.disconnectPeer.bind(this), 5 * 1000);
	};

	SSTPPeer.prototype.setDisconnectStateTimer2 = function () {
		this.timers.disconnectStateTimer2 = setTimeout(this.disconnectPeer.bind(this), 1 * 1000);
	};

	SSTPPeer.prototype.setHelloTimer = function () {
		this.timers.helloTimer = setTimeout(this.sendEchoRequest.bind(this), 60 * 1000);
	};

	SSTPPeer.prototype.closePeer = function () {
		this.pppd.kill();

		for (let timer in this.timers) {
			if (this.timers.hasOwnProperty(timer)) {
				clearTimeout(this.timers[timer]);
				delete this.timers[timer];
			}
		}
	};

	SSTPPeer.prototype.disconnectPeer = function () {
		this.stream.end();
		this.currentState = this.knownStates.SERVER_CALL_DISCONNECTED;
		IPv4Pool[this.IPv4Addr] = false;
		this.closePeer();
	};

	SSTPPeer.prototype.abortCall = function () {
		if (! (
			this.currentState === this.knownStates.CALL_ABORT_TIMEOUT_PENDING ||
			this.currentState === this.knownStates.CALL_ABORT_PENDING ||
			this.currentState === this.knownStates.CALL_DISCONNECT_ACK_PENDING ||
			this.currentState === this.knownStates.CALL_DISCONNECT_TIMEOUT_PENDING
		)) {
			this.currentState = this.knownStates.CALL_ABORT_IN_PROGRESS_1;
			this.sendCallAbort();
			this.setAbortStateTimer1();
			this.currentState = this.knownStates.CALL_ABORT_PENDING;
		}
	};

	SSTPPeer.prototype.sendSSTPData = function (data) {
		if (this.currentState === this.knownStates.SERVER_CALL_CONNECTED || this.currentState === this.knownStates.SERVER_CALL_CONNECTED_PENDING) {
			var dataHeader = new Buffer(4);

			dataHeader[0] = this.serverVersion;
			dataHeader[1] = 0x0;
			dataHeader.writeUInt16BE(4 + data.length, 2);

			this.stream.write(Buffer.concat([dataHeader, data], dataHeader.length + data.length));
		}
	};

	SSTPPeer.prototype.onTunnelDisconnection = function () {
		this.currentState = this.knownStates.CALL_DISCONNECT_IN_PROGRESS_1;
		this.sendCallDisconnect();
		this.currentState = this.knownStates.CALL_DISCONNECT_ACK_PENDING;
	};

	SSTPPeer.prototype.PPPFCSTable = (function () {
		var ret = [],
		P = 0x8408;

		for (let b = 0; b < 256; b += 1) {
			let v = b;

			for (let i = 8; i > 0; i -= 1) {
				v = v & 1 ? (v >> 1) ^ P : v >> 1;
			}

			ret.push(v & 0xffff);
		}

		return ret;
	})();

	SSTPPeer.prototype.calcPPPFCSBits = function (data) {
		var fcs = 0xffff;

		for (let i = 0; i < data.length; i += 1) {
			fcs = (fcs >> 8) ^ this.PPPFCSTable[(fcs ^ data[i]) & 0xff];
		}

		fcs ^= 0xffff;

		return new Buffer([fcs & 0x00ff, (fcs >> 8) & 0x00ff]);
	};

	SSTPPeer.prototype.escapePPPFrame = function (data) {
		var ret = [], toEscape = Buffer.concat([data, this.calcPPPFCSBits(data)], data.length + 2);

		ret.push(0x7e);

		for (let i = 0; i < toEscape.length; i += 1) {
			if (toEscape[i] === 0x7e || toEscape[i] === 0x7d || toEscape[i] < 0x20) {
				ret.push(0x7d);
				ret.push(toEscape[i] ^ 0x20);
			} else {
				ret.push(toEscape[i]);
			}
		}

		ret.push(0x7e);

		return new Buffer(ret);
	};

	SSTPPeer.prototype.unescapePPPFrame = function (data) {
		var ret = [], i = 0, seenFlags = this.pppProcessingLargeFrame ? 1 : 0;

		if (this.pppLastOctetIsEscape) {
			ret.push(data[i] ^ 0x20);
			i += 1;
		}

		for (; i < data.length; i += 1) {
			switch (data[i]) {
				case 0x7e:
					seenFlags += 1;
					if (seenFlags === 2) {
						ret.slice(0, -2);
						seenFlags = 0;
					}
					break;
				case 0x7d:
					ret.push(data[i += 1] ^ 0x20);
					break;
				default:
					ret.push(data[i]);
			}
		}

		this.pppProcessingLargeFrame = (seenFlags === 1);

		return new Buffer(ret);
	};

	SSTPPeer.prototype.processIncomingPPPFrame = function (data) {
		if (this.pppd !== null && ! this.pppd.killed) {
			this.pppd.stdin.write(this.escapePPPFrame(data));
		}
	};

	SSTPPeer.prototype.forwardPPPDOutput = function (data) {
		this.sendSSTPData(this.unescapePPPFrame(data));
		this.pppLastOctetIsEscape = (data[data.length] === 0x7d);
	};

	SSTPPeer.prototype.initPPPD = function (options) {
		this.pppd = child_process.spawn("pppd", [
			"notty",
			"file",
			"options.sstpd",
			// "+ipv6",
			"refuse-pap",
			"refuse-mschap",
			"refuse-mschap-v2",
			"refuse-eap",
			"require-chap",
			"nodefaultroute",
			"proxyarp",
			"debug",
			CONFIG.serverV4 + ":" + this.IPv4Addr
		]);

		this.pppd.stdout.on("data", this.forwardPPPDOutput.bind(this));
		this.pppd.stderr.on("data", function (data) { console.log(data.toString()); });
		this.pppd.on("end", this.onTunnelDisconnection.bind(this));
		this.pppd.stdin.on("error", function (e) { console.log(e.stack); });
	};

	SSTPPeer.prototype.respondSSTPControlMessage = function (rMsg) {
		var rCMsg = this.parseSSTPControlMessage(rMsg);

		if (rCMsg === null) {
			this.abortCall();
			return;
		}

		switch (rCMsg.messageType) {
			case 0x0001:
				if (this.currentState === this.knownStates.SERVER_CONNECT_REQUEST_PENDING) {
					if (rCMsg.isValidMessage) {
						this.sendCallConnectACK();
						this.currentState = this.knownStates.SERVER_CALL_CONNECTED_PENDING;
						this.initPPPD();
					} else {
						this.sendCallConnectNAK();
					}
				} else {
					this.abortCall();
				}
				break;

			case 0x0004:
				if (
					this.currentState === this.knownStates.SERVER_CALL_CONNECTED_PENDING &&
					rCMsg.isValidMessage &&
					rCMsg.attributes[0].value.nonce.toString("hex") === this.nonce.toString("hex") &&
					rCMsg.attributes[0].value.certHash.toString("hex") === this.serverCertificateHash.toString("hex") &&
					rCMsg.attributes[0].value.hashProtocol === this.serverHashProtocolSupported &&
					true // NOTE: Received Compound MAC will not be verified
				) {
					clearTimeout(this.timers.negotiationTimer);
					this.currentState = this.knownStates.SERVER_CALL_CONNECTED;
					this.setHelloTimer();
				} else {
					this.abortCall();
				}
				break;

			case 0x0005:
				if (this.currentState === this.knownStates.CALL_ABORT_PENDING) {
					clearTimeout(this.timers.abortStateTimer1);
					this.setAbortStateTimer2();
					this.currentState = this.knownStates.CALL_ABORT_TIMEOUT_PENDING;
				} else if (this.currentState !== this.knownStates.CALL_ABORT_TIMEOUT_PENDING && this.currentState !== this.knownStates.CALL_DISCONNECT_TIMEOUT_PENDING) {
					this.currentState = this.knownStates.CALL_ABORT_IN_PROGRESS_2;
					this.sendCallAbort();
					this.setAbortStateTimer2();
					this.currentState = this.knownStates.CALL_ABORT_TIMEOUT_PENDING;
				}
				break;

			case 0x0006:
				if (this.currentState === this.knownStates.CALL_DISCONNECT_ACK_PENDING) {
					clearTimeout(this.timers.disconnectStateTimer1);
					this.currentState = this.knownStates.CALL_DISCONNECT_IN_PROGRESS_2;
					this.sendCallDisconnectACK();
					this.setDisconnectStateTimer2();
					this.currentState = this.knownStates.CALL_DISCONNECT_TIMEOUT_PENDING;
				} else if (
					this.currentState !== this.knownStates.CALL_ABORT_PENDING &&
					this.currentState !== this.knownStates.CALL_ABORT_PENDING &&
					this.currentState !== this.knownStates.CALL_DISCONNECT_TIMEOUT_PENDING
				) {
					this.currentState = this.knownStates.CALL_DISCONNECT_IN_PROGRESS_2;
					this.sendCallDisconnectACK();
					this.setDisconnectStateTimer2();
					this.currentState = this.knownStates.CALL_DISCONNECT_TIMEOUT_PENDING;
				}
				break;

			case 0x0007:
				if (this.currentState === this.knownStates.CALL_DISCONNECT_ACK_PENDING) {
					this.disconnectPeer();
				} else {
					this.abortCall();
				}
				break;

			case 0x0008:
				if (this.currentState === this.knownStates.SERVER_CALL_CONNECTED) {
					clearTimeout(this.timers.helloTimer);
					this.setHelloTimer();
					this.sendEchoResponse();
				} else {
					this.abortCall();
				}
				break;

			case 0x0009:
				if (this.currentState === this.knownStates.SERVER_CALL_CONNECTED) {
					clearTimeout(this.timers.helloTimer);
					this.setHelloTimer();
				} else {
					this.abortCall();
				}
				break;

			default:
				this.abortCall();
				break;
		}

		return;
	};

	SSTPPeer.prototype.inputParser = function (data) {
		this.sstpFifo.push(data);

		if (this.currentState === this.knownStates.STANDBY) {
			this.parseHTTPHeaderInSSTPFifo();

			if (this.currentState === this.knownStates.HTTPS_REJECTED) {
				this.stream.end("400 Bad Request HTTP/1.1\r\n\r\n");
				return;
			}
		}

		if (this.currentState === this.knownStates.HTTPS_OPENED) {
			if(! this.isAcceptableHTTPSRequest()) {
				this.stream.end("HTTP/1.1 406 Not Acceptable\r\n\r\n");
				return;
			} else {
				this.stream.write("HTTP/1.1 200 OK\r\n");
				this.stream.write("Content-Length: " + (this.requestHeader["Content-Length"] || 0) + "\r\n");
				this.stream.write("Server: " + CONST.prodName + "\r\n");
				this.stream.write("Data: " + new Date().toUTCString() + "\r\n");
				this.stream.write("\r\n");

				this.currentState = this.knownStates.SERVER_CONNECT_REQUEST_PENDING;
				this.setNegotiationTimer();
			}

			if (this.sstpFifo.length === 0) {
				return;
			}
		}

		if (this.currentState > this.knownStates.HTTPS_OPENED) {
			let message = null;

			while (message = this.fetchSSTPMsgFromFIFO()) {
				if (message.version !== this.serverVersion) {
					this.abortCall(this);
				}

				if (message.isControl) {
					this.respondSSTPControlMessage(message);
				} else {
					this.processIncomingPPPFrame(message.data);
				}
			}
		}
	};

	(function () {
		var TLSOptions = {
			key : CONST.key,
			cert : CONST.cert,
			ciphers : CONST.TLSCiphers
		},

		server = tls.createServer(TLSOptions, function (stream) {
			new SSTPPeer(stream);
		});

		CONFIG.serverAddr.forEach(function (addr) {
			server.listen(CONFIG.port, addr);
		});
	})();
})();
