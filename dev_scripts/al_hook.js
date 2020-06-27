var loadPak_ptr = 0x7B6FFC;
var decompressStringTable_ptr = 0x8134B4;
var readCRC_ptr = 0x7B3580;

var readFunction_ptr = 0x7BDA4C;

// IFF2 Stuff
var Iff2DataFileReaderEnterChunk_ptr = 0x7B9DB0;
var Iff2DataFileReaderEnterForm_ptr = 0x7B987C;

// Read sub
var Iff2DataFileReaderNamespaceReadShort_ptr = 0x7BA30A;
var Iff2DataFileReaderNamespaceReadShortv2_ptr = 0x7BA478;
var Iff2DataFileReaderNamespaceReadLong_ptr = 0x7BA23E;
var Iff2DataFileReaderNamespaceReadInt_ptr = 0x7BA300;
var Iff2DataFileReaderNamespaceReadByte_ptr = 0x7BA3C0;
var Iff2DataFileReaderNamespaceReadBytev2_ptr = 0x7BA530;
var Iff2DataFileReaderNamespaceReadIntSwaped_ptr = 0x7BA5E8;
var Iff2DataFileReaderNamespaceReadString_ptr = 0x7BA6A8;

// PakIFF Stuff (PIFF)
var PakIffDataFileReaderEnterForm_ptr = 0x7BC1DC;
var PakIffDataFileReaderEnterChunk_ptr = 0x7BC710;

// Read sub
var PakIffDataFileReaderNamespaceReadLong_ptr = 0x7BCB9E;
var PakIffDataFileReaderNamespaceReadInt_ptr = 0x7BCC60;
var PakIffDataFileReaderNamespaceReadShortv2_ptr = 0x7BCC6A;
var PakIffDataFileReaderNamespaceReadByte_ptr = 0x7BCD20;
var PakIffDataFileReaderNamespaceReadShortv3_ptr = 0x7BCDD8;
var PakIffDataFileReaderNamespaceReadBytev2_ptr = 0x7BCE90;
var PakIffDataFileReaderNamespaceReadIntv2_ptr = 0x7BCF48;
var PakIffDataFileReaderNamespaceReadString_ptr = 0x7BD080;


function hexToBytes(hex) {
	var hex = hex.substr(2, hex.length);

    for (var bytes = [], c = 0; c < hex.length; c += 2)
	    bytes.push(parseInt(hex.substr(c, 2), 16));
    
    return bytes;
}

function getCharFromHex(hex) {
	var barray = hexToBytes(hex.toString());
	return String.fromCharCode.apply(null, barray.reverse());
}

function getBacktrace(context) {
	return Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n');
}


var bytes_read_on_handler = {};

var current_iff_chunk_tag = undefined;
var current_iff_form_tag = undefined;

var current_piff_chunk_tag = undefined;
var current_piff_form_tag = undefined;

var wanted_iff_chunk_tag = undefined;
var wanted_iff_form_tag = undefined;

var wanted_piff_chunk_tag = undefined;
var wanted_piff_form_tag = undefined;


Java.perform(function() {
	console.log("[*] Setting up java side hook");

	var ArcaneLegends = Java.use("sts.al.ArcaneLegends");

	ArcaneLegends.onCreate.implementation = function(bundle) {
		console.log("[*] onCreate got called");

		this.onCreate(bundle);

		var lib_base = Process.findModuleByName("libarcanelegends.so").base;
		console.log("[*] Lib base address " + lib_base);

		Interceptor.attach(ptr(lib_base.add(loadPak_ptr + 1)), {
			onEnter: function(args) {
				console.log("*** LoadPak called on file: " + Memory.readUtf8String(args[1]));
			}
		});

		Interceptor.attach(ptr(lib_base.add(readFunction_ptr + 1)), {
			onEnter: function(args) {
				if (bytes_read_on_handler[args[0]] == undefined) {
					bytes_read_on_handler[args[0]] = parseInt(args[2]);
				}
				else {
					bytes_read_on_handler[args[0]] += parseInt(args[2]);
				}

				console.log("Read called on hander " + args[0] + ", bytes to read: " + parseInt(args[2]) + ", total bytes read on this handler: " + bytes_read_on_handler[args[0]]);
			}
		})

		Interceptor.attach(ptr(lib_base.add(decompressStringTable_ptr + 1)), {
			onEnter: function(args) {
				this.output_buffer_ptr = args[1];
				this.uncompressed_size = parseInt(args[2], 16);
				console.log('*** Decompression started, file version: ' + args[0] + ' uncompressed size: ' + args[2] + ' compressed size: ' + parseInt(args[4], 16));
			}
		})

		// IFF hooks

		Interceptor.attach(ptr(lib_base.add(Iff2DataFileReaderEnterForm_ptr + 1)), {
			onEnter: function(args) {
				var tag = getCharFromHex(args[1]);

				current_iff_form_tag = tag

				if (wanted_iff_form_tag != undefined) {
					if (wanted_iff_form_tag != current_iff_form_tag) {
						return
					}
				}

				console.log('[*] Iff2DataFileReader::enterForm() called on tag: ' + tag);
			}
		})

		Interceptor.attach(ptr(lib_base.add(Iff2DataFileReaderEnterChunk_ptr + 1)), {
			onEnter: function(args) {
				var tag = getCharFromHex(args[1]);

				current_iff_chunk_tag = tag;

				if (wanted_iff_chunk_tag != undefined) {
					if (wanted_iff_chunk_tag != current_iff_chunk_tag) {
						return
					}
				}

				console.log('[*] Iff2DataFileReader::enterChunk() called on tag: ' + tag);
			}
		})

		Interceptor.attach(ptr(lib_base.add(PakIffDataFileReaderEnterForm_ptr + 1)), {
			onEnter: function(args) {
				var tag = getCharFromHex(args[1]);

				current_piff_form_tag = tag;

				if (wanted_piff_form_tag != undefined) {
					if (wanted_piff_form_tag != current_piff_form_tag) {
						return
					}
				}

				console.log('[*] PakIffDataFileReader::enterForm() called on tag: ' + tag);
			}
		})

		Interceptor.attach(ptr(lib_base.add(PakIffDataFileReaderEnterChunk_ptr + 1)), {
			onEnter: function(args) {
				var tag = getCharFromHex(args[1])

				current_piff_chunk_tag = tag;

				if (wanted_piff_chunk_tag != undefined) {
					if (wanted_piff_chunk_tag != current_piff_chunk_tag) {
						return
					}
				}

				console.log('[*] PakIffDataFileReader::enterChunk() called on tag: ' + tag);
			}
		})

		Interceptor.attach(ptr(lib_base.add(PakIffDataFileReaderNamespaceReadLong_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_piff_chunk_tag != undefined) {
					if (wanted_piff_chunk_tag != current_piff_chunk_tag) {
						return
					}
				}

				console.log('[*] PakIffDataFileReaderNamespace::readLong() called !');
			}
		})

		Interceptor.attach(ptr(lib_base.add(PakIffDataFileReaderNamespaceReadInt_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_piff_chunk_tag != undefined) {
					if (wanted_piff_chunk_tag != current_piff_chunk_tag) {
						return
					}
				}

				console.log('[*] PakIffDataFileReaderNamespace::readInt() called !');
			}
		})

		Interceptor.attach(ptr(lib_base.add(PakIffDataFileReaderNamespaceReadShortv2_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_piff_chunk_tag != undefined) {
					if (wanted_piff_chunk_tag != current_piff_chunk_tag) {
						return
					}
				}

				console.log('[*] PakIffDataFileReaderNamespace::readShortV2() called !');
			}
		})

		Interceptor.attach(ptr(lib_base.add(PakIffDataFileReaderNamespaceReadByte_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_piff_chunk_tag != undefined) {
					if (wanted_piff_chunk_tag != current_piff_chunk_tag) {
						return
					}
				}

				console.log('[*] PakIffDataFileReaderNamespace::readByte() called !');
			}
		})

		Interceptor.attach(ptr(lib_base.add(PakIffDataFileReaderNamespaceReadShortv3_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_piff_chunk_tag != undefined) {
					if (wanted_piff_chunk_tag != current_piff_chunk_tag) {
						return
					}
				}
				
				console.log('[*] PakIffDataFileReaderNamespace::readShortV3() called !');
			}
		})

		Interceptor.attach(ptr(lib_base.add(PakIffDataFileReaderNamespaceReadBytev2_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_piff_chunk_tag != undefined) {
					if (wanted_piff_chunk_tag != current_piff_chunk_tag) {
						return
					}
				}

				console.log('[*] PakIffDataFileReaderNamespace::readByteV2() called !');
			}
		})

		Interceptor.attach(ptr(lib_base.add(PakIffDataFileReaderNamespaceReadIntv2_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_piff_chunk_tag != undefined) {
					if (wanted_piff_chunk_tag != current_piff_chunk_tag) {
						return
					}
				}

				console.log('[*] PakIffDataFileReaderNamespace::readIntV2() called !');
			}
		})

		Interceptor.attach(ptr(lib_base.add(PakIffDataFileReaderNamespaceReadString_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_piff_chunk_tag != undefined) {
					if (wanted_piff_chunk_tag != current_piff_chunk_tag) {
						return
					}
				}

				console.log('[*] PakIffDataFileReaderNamespace::readString() called !');
				console.log('[*] Called by: ' + getBacktrace(this.context));

			}
		})

		Interceptor.attach(ptr(lib_base.add(Iff2DataFileReaderNamespaceReadShort_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_iff_chunk_tag != undefined) {
					if (wanted_iff_chunk_tag != current_iff_chunk_tag) {
						return
					}
				}

				console.log('[*] Iff2DataFileReader::readShort() called !');
			}
		})

		Interceptor.attach(ptr(lib_base.add(Iff2DataFileReaderNamespaceReadShortv2_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_iff_chunk_tag != undefined) {
					if (wanted_iff_chunk_tag != current_iff_chunk_tag) {
						return
					}
				}

				console.log('[*] Iff2DataFileReader::readShortV2() called !');
			}
		})

		Interceptor.attach(ptr(lib_base.add(Iff2DataFileReaderNamespaceReadLong_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_iff_chunk_tag != undefined) {
					if (wanted_iff_chunk_tag != current_iff_chunk_tag) {
						return
					}
				}

				console.log('[*] Iff2DataFileReader::readLong() called !');
			}
		})

		Interceptor.attach(ptr(lib_base.add(Iff2DataFileReaderNamespaceReadInt_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_iff_chunk_tag != undefined) {
					if (wanted_iff_chunk_tag != current_iff_chunk_tag) {
						return
					}
				}

				console.log('[*] Iff2DataFileReader::readInt() called !');
			}
		})

		Interceptor.attach(ptr(lib_base.add(Iff2DataFileReaderNamespaceReadByte_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_iff_chunk_tag != undefined) {
					if (wanted_iff_chunk_tag != current_iff_chunk_tag) {
						return
					}
				}

				console.log('[*] Iff2DataFileReader::readByte() called !');
			}
		})

		Interceptor.attach(ptr(lib_base.add(Iff2DataFileReaderNamespaceReadBytev2_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_iff_chunk_tag != undefined) {
					if (wanted_iff_chunk_tag != current_iff_chunk_tag) {
						return
					}
				}

				console.log('[*] Iff2DataFileReader::readByteV2() called !');
			}
		})

		Interceptor.attach(ptr(lib_base.add(Iff2DataFileReaderNamespaceReadIntSwaped_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_iff_chunk_tag != undefined) {
					if (wanted_iff_chunk_tag != current_iff_chunk_tag) {
						return
					}
				}

				console.log('[*] Iff2DataFileReader::readIntSwaped() called !');
			}
		})

		Interceptor.attach(ptr(lib_base.add(Iff2DataFileReaderNamespaceReadString_ptr + 1)), {
			onEnter: function(args) {
				if (wanted_iff_chunk_tag != undefined) {
					if (wanted_iff_chunk_tag != current_iff_chunk_tag) {
						return
					}
				}

				console.log('[*] Iff2DataFileReader::readString() called !');
			}
		})
	}
})
