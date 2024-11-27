TEST_VECTORS = {
	"salsa" : [
		# testVectors was taken from set 6 of the ECRYPT test vectors:
		# http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/salsa20/full/verified.test-vectors?logsort=rev&rev=210&view=markup
		{
			"key" : [0x00, 0x53, 0xA6, 0xF9, 0x4C, 0x9F, 0xF2, 0x45, 0x98, 0xEB, 0x3E, 0x91, 0xE4, 0x37, 0x8A, 0xDD, 0x30, 0x83, 0xD6, 0x29, 0x7C, 0xCF, 0x22, 0x75, 0xC8, 0x1B, 0x6E, 0xC1, 0x14, 0x67, 0xBA, 0x0D],
			"nonce" : [0x0D, 0x74, 0xDB, 0x42, 0xA9, 0x10, 0x77, 0xDE],
			"message" : [0xC3, 0x49, 0xB6, 0xA5, 0x1A, 0x3E, 0xC9, 0xB7, 0x12, 0xEA, 0xED, 0x3F, 0x90, 0xD8, 0xBC, 0xEE, 0x69, 0xB7, 0x62, 0x86, 0x45, 0xF2, 0x51, 0xA9, 0x96, 0xF5, 0x52, 0x60, 0xC6, 0x2E, 0xF3, 0x1F, 0xD6, 0xC6, 0xB0, 0xAE, 0xA9, 0x4E, 0x13, 0x6C, 0x9D, 0x98, 0x4A, 0xD2, 0xDF, 0x35, 0x78, 0xF7, 0x8E, 0x45, 0x75, 0x27, 0xB0, 0x3A, 0x04, 0x50, 0x58, 0x0D, 0xD8, 0x74, 0xF6, 0x3B, 0x1A, 0xB9]
		},
		{
			"key" : [0x05, 0x58, 0xAB, 0xFE, 0x51, 0xA4, 0xF7, 0x4A, 0x9D, 0xF0, 0x43, 0x96, 0xE9, 0x3C, 0x8F, 0xE2, 0x35, 0x88, 0xDB, 0x2E, 0x81, 0xD4, 0x27, 0x7A, 0xCD, 0x20, 0x73, 0xC6, 0x19, 0x6C, 0xBF, 0x12],
			"nonce" : [0x16, 0x7D, 0xE4, 0x4B, 0xB2, 0x19, 0x80, 0xE7],
			"message" : [0xC3, 0xEA, 0xAF, 0x32, 0x83, 0x6B, 0xAC, 0xE3, 0x2D, 0x04, 0xE1, 0x12, 0x42, 0x31, 0xEF, 0x47, 0xE1, 0x01, 0x36, 0x7D, 0x63, 0x05, 0x41, 0x3A, 0x0E, 0xEB, 0x07, 0xC6, 0x06, 0x98, 0xA2, 0x87, 0x6E, 0x4D, 0x03, 0x18, 0x70, 0xA7, 0x39, 0xD6, 0xFF, 0xDD, 0xD2, 0x08, 0x59, 0x7A, 0xFF, 0x0A, 0x47, 0xAC, 0x17, 0xED, 0xB0, 0x16, 0x7D, 0xD6, 0x7E, 0xBA, 0x84, 0xF1, 0x88, 0x3D, 0x4D, 0xFD]
		},
		{
			"key" : [0x0A, 0x5D, 0xB0, 0x03, 0x56, 0xA9, 0xFC, 0x4F, 0xA2, 0xF5, 0x48, 0x9B, 0xEE, 0x41, 0x94, 0xE7, 0x3A, 0x8D, 0xE0, 0x33, 0x86, 0xD9, 0x2C, 0x7F, 0xD2, 0x25, 0x78, 0xCB, 0x1E, 0x71, 0xC4, 0x17],
			"nonce" : [0x1F, 0x86, 0xED, 0x54, 0xBB, 0x22, 0x89, 0xF0],
			"message" : [0x3C, 0xD2, 0x3C, 0x3D, 0xC9, 0x02, 0x01, 0xAC, 0xC0, 0xCF, 0x49, 0xB4, 0x40, 0xB6, 0xC4, 0x17, 0xF0, 0xDC, 0x8D, 0x84, 0x10, 0xA7, 0x16, 0xD5, 0x31, 0x4C, 0x05, 0x9E, 0x14, 0xB1, 0xA8, 0xD9, 0xA9, 0xFB, 0x8E, 0xA3, 0xD9, 0xC8, 0xDA, 0xE1, 0x2B, 0x21, 0x40, 0x2F, 0x67, 0x4A, 0xA9, 0x5C, 0x67, 0xB1, 0xFC, 0x51, 0x4E, 0x99, 0x4C, 0x9D, 0x3F, 0x3A, 0x6E, 0x41, 0xDF, 0xF5, 0xBB, 0xA6]
		},
		{
			"key" : [0x0F, 0x62, 0xB5, 0x08, 0x5B, 0xAE, 0x01, 0x54, 0xA7, 0xFA, 0x4D, 0xA0, 0xF3, 0x46, 0x99, 0xEC, 0x3F, 0x92, 0xE5, 0x38, 0x8B, 0xDE, 0x31, 0x84, 0xD7, 0x2A, 0x7D, 0xD0, 0x23, 0x76, 0xC9, 0x1C, ],
			"nonce" : [0x28, 0x8F, 0xF6, 0x5D, 0xC4, 0x2B, 0x92, 0xF9],
			"message" : [0xE0, 0x0E, 0xBC, 0xCD, 0x70, 0xD6, 0x91, 0x52, 0x72, 0x5F, 0x99, 0x87, 0x98, 0x21, 0x78, 0xA2, 0xE2, 0xE1, 0x39, 0xC7, 0xBC, 0xBE, 0x04, 0xCA, 0x8A, 0x0E, 0x99, 0xE3, 0x18, 0xD9, 0xAB, 0x76, 0xF9, 0x88, 0xC8, 0x54, 0x9F, 0x75, 0xAD, 0xD7, 0x90, 0xBA, 0x4F, 0x81, 0xC1, 0x76, 0xDA, 0x65, 0x3C, 0x1A, 0x04, 0x3F, 0x11, 0xA9, 0x58, 0xE1, 0x69, 0xB6, 0xD2, 0x31, 0x9F, 0x4E, 0xEC, 0x1A]
		},
	],
	"x25519" : [
		# testVectors generated with BoringSSL.	
		{
			"public_key" : [0x66, 0x8f, 0xb9, 0xf7, 0x6a, 0xd9, 0x71, 0xc8, 0x1a, 0xc9, 0x0, 0x7, 0x1a, 0x15, 0x60, 0xbc, 0xe2, 0xca, 0x0, 0xca, 0xc7, 0xe6, 0x7a, 0xf9, 0x93, 0x48, 0x91, 0x37, 0x61, 0x43, 0x40, 0x14],
			"secret_key" : [0xdb, 0x5f, 0x32, 0xb7, 0xf8, 0x41, 0xe7, 0xa1, 0xa0, 0x9, 0x68, 0xef, 0xfd, 0xed, 0x12, 0x73, 0x5f, 0xc4, 0x7a, 0x3e, 0xb1, 0x3b, 0x57, 0x9a, 0xac, 0xad, 0xea, 0xe8, 0x9, 0x39, 0xa7, 0xdd],
		},
		{
			"public_key" : [0x63, 0x66, 0x95, 0xe3, 0x4f, 0x75, 0xb9, 0xa2, 0x79, 0xc8, 0x70, 0x6f, 0xad, 0x12, 0x89, 0xf2, 0xc0, 0xb1, 0xe2, 0x2e, 0x16, 0xf8, 0xb8, 0x86, 0x17, 0x29, 0xc1, 0xa, 0x58, 0x29, 0x58, 0xaf],
			"secret_key" : [0x9, 0xd, 0x7, 0x1, 0xf8, 0xfd, 0xe2, 0x8f, 0x70, 0x4, 0x3b, 0x83, 0xf2, 0x34, 0x62, 0x25, 0x41, 0x9b, 0x18, 0xa7, 0xf2, 0x7e, 0x9e, 0x3d, 0x2b, 0xfd, 0x4, 0xe1, 0xf, 0x3d, 0x21, 0x3e],
		},
		{
			"public_key" : [0x73, 0x41, 0x81, 0xcd, 0x1a, 0x94, 0x6, 0x52, 0x2a, 0x56, 0xfe, 0x25, 0xe4, 0x3e, 0xcb, 0xf0, 0x29, 0x5d, 0xb5, 0xdd, 0xd0, 0x60, 0x9b, 0x3c, 0x2b, 0x4e, 0x79, 0xc0, 0x6f, 0x8b, 0xd4, 0x6d],
			"secret_key" : [0xf8, 0xa8, 0x42, 0x1c, 0x7d, 0x21, 0xa9, 0x2d, 0xb3, 0xed, 0xe9, 0x79, 0xe1, 0xfa, 0x6a, 0xcb, 0x6, 0x2b, 0x56, 0xb1, 0x88, 0x5c, 0x71, 0xc5, 0x11, 0x53, 0xcc, 0xb8, 0x80, 0xac, 0x73, 0x15],
		},
		{
			"public_key" : [0x1f, 0x70, 0x39, 0x1f, 0x6b, 0xa8, 0x58, 0x12, 0x94, 0x13, 0xbd, 0x80, 0x1b, 0x12, 0xac, 0xbf, 0x66, 0x23, 0x62, 0x82, 0x5c, 0xa2, 0x50, 0x9c, 0x81, 0x87, 0x59, 0xa, 0x2b, 0xe, 0x61, 0x72],
			"secret_key" : [0xd3, 0xea, 0xd0, 0x7a, 0x0, 0x8, 0xf4, 0x45, 0x2, 0xd5, 0x80, 0x8b, 0xff, 0xc8, 0x97, 0x9f, 0x25, 0xa8, 0x59, 0xd5, 0xad, 0xf4, 0x31, 0x2e, 0xa4, 0x87, 0x48, 0x9c, 0x30, 0xe0, 0x1b, 0x3b],
		},
		{
			"public_key" : [0x3a, 0x7a, 0xe6, 0xcf, 0x8b, 0x88, 0x9d, 0x2b, 0x7a, 0x60, 0xa4, 0x70, 0xad, 0x6a, 0xd9, 0x99, 0x20, 0x6b, 0xf5, 0x7d, 0x90, 0x30, 0xdd, 0xf7, 0xf8, 0x68, 0xc, 0x8b, 0x1a, 0x64, 0x5d, 0xaa],
			"secret_key" : [0x4d, 0x25, 0x4c, 0x80, 0x83, 0xd8, 0x7f, 0x1a, 0x9b, 0x3e, 0xa7, 0x31, 0xef, 0xcf, 0xf8, 0xa6, 0xf2, 0x31, 0x2d, 0x6f, 0xed, 0x68, 0xe, 0xf8, 0x29, 0x18, 0x51, 0x61, 0xc8, 0xfc, 0x50, 0x60],
		},
		{
			"public_key" : [0x20, 0x31, 0x61, 0xc3, 0x15, 0x9a, 0x87, 0x6a, 0x2b, 0xea, 0xec, 0x29, 0xd2, 0x42, 0x7f, 0xb0, 0xc7, 0xc3, 0xd, 0x38, 0x2c, 0xd0, 0x13, 0xd2, 0x7c, 0xc3, 0xd3, 0x93, 0xdb, 0xd, 0xaf, 0x6f],
			"secret_key" : [0x6a, 0xb9, 0x5d, 0x1a, 0xbe, 0x68, 0xc0, 0x9b, 0x0, 0x5c, 0x3d, 0xb9, 0x4, 0x2c, 0xc9, 0x1a, 0xc8, 0x49, 0xf7, 0xe9, 0x4a, 0x2a, 0x4a, 0x9b, 0x89, 0x36, 0x78, 0x97, 0xb, 0x7b, 0x95, 0xbf],
		},
		{
			"public_key" : [0x13, 0xd6, 0x54, 0x91, 0xfe, 0x75, 0xf2, 0x3, 0xa0, 0x8, 0xb4, 0x41, 0x5a, 0xbc, 0x60, 0xd5, 0x32, 0xe6, 0x95, 0xdb, 0xd2, 0xf1, 0xe8, 0x3, 0xac, 0xcb, 0x34, 0xb2, 0xb7, 0x2c, 0x3d, 0x70],
			"secret_key" : [0x2e, 0x78, 0x4e, 0x4, 0xca, 0x0, 0x73, 0x33, 0x62, 0x56, 0xa8, 0x39, 0x25, 0x5e, 0xd2, 0xf7, 0xd4, 0x79, 0x6a, 0x64, 0xcd, 0xc3, 0x7f, 0x1e, 0xb0, 0xe5, 0xc4, 0xc8, 0xd1, 0xd1, 0xe0, 0xf5],
		},
		{
			"public_key" : [0x68, 0x6f, 0x7d, 0xa9, 0x3b, 0xf2, 0x68, 0xe5, 0x88, 0x6, 0x98, 0x31, 0xf0, 0x47, 0x16, 0x3f, 0x33, 0x58, 0x99, 0x89, 0xd0, 0x82, 0x6e, 0x98, 0x8, 0xfb, 0x67, 0x8e, 0xd5, 0x7e, 0x67, 0x49],
			"secret_key" : [0x8b, 0x54, 0x9b, 0x2d, 0xf6, 0x42, 0xd3, 0xb2, 0x5f, 0xe8, 0x38, 0xf, 0x8c, 0xc4, 0x37, 0x5f, 0x99, 0xb7, 0xbb, 0x4d, 0x27, 0x5f, 0x77, 0x9f, 0x3b, 0x7c, 0x81, 0xb8, 0xa2, 0xbb, 0xc1, 0x29],
		},
		{
			"public_key" : [0x82, 0xd6, 0x1c, 0xce, 0xdc, 0x80, 0x6a, 0x60, 0x60, 0xa3, 0x34, 0x9a, 0x5e, 0x87, 0xcb, 0xc7, 0xac, 0x11, 0x5e, 0x4f, 0x87, 0x77, 0x62, 0x50, 0xae, 0x25, 0x60, 0x98, 0xa7, 0xc4, 0x49, 0x59],
			"secret_key" : [0x8b, 0x6b, 0x9d, 0x8, 0xf6, 0x1f, 0xc9, 0x1f, 0xe8, 0xb3, 0x29, 0x53, 0xc4, 0x23, 0x40, 0xf0, 0x7, 0xb5, 0x71, 0xdc, 0xb0, 0xa5, 0x6d, 0x10, 0x72, 0x4e, 0xce, 0xf9, 0x95, 0xc, 0xfb, 0x25],
		},
		{
			"public_key" : [0x7d, 0xc7, 0x64, 0x4, 0x83, 0x13, 0x97, 0xd5, 0x88, 0x4f, 0xdf, 0x6f, 0x97, 0xe1, 0x74, 0x4c, 0x9e, 0xb1, 0x18, 0xa3, 0x1a, 0x7b, 0x23, 0xf8, 0xd7, 0x9f, 0x48, 0xce, 0x9c, 0xad, 0x15, 0x4b],
			"secret_key" : [0x1a, 0xcd, 0x29, 0x27, 0x84, 0xf4, 0x79, 0x19, 0xd4, 0x55, 0xf8, 0x87, 0x44, 0x83, 0x58, 0x61, 0xb, 0xb9, 0x45, 0x96, 0x70, 0xeb, 0x99, 0xde, 0xe4, 0x60, 0x5, 0xf6, 0x89, 0xca, 0x5f, 0xb6],
		},
		{
			"public_key" : [0xfb, 0xc4, 0x51, 0x1d, 0x23, 0xa6, 0x82, 0xae, 0x4e, 0xfd, 0x8, 0xc8, 0x17, 0x9c, 0x1c, 0x6, 0x7f, 0x9c, 0x8b, 0xe7, 0x9b, 0xbc, 0x4e, 0xff, 0x5c, 0xe2, 0x96, 0xc6, 0xbc, 0x1f, 0xf4, 0x45],
			"secret_key" : [0x55, 0xca, 0xff, 0x21, 0x81, 0xf2, 0x13, 0x6b, 0xe, 0xd0, 0xe1, 0xe2, 0x99, 0x44, 0x48, 0xe1, 0x6c, 0xc9, 0x70, 0x64, 0x6a, 0x98, 0x3d, 0x14, 0xd, 0xc4, 0xea, 0xb3, 0xd9, 0x4c, 0x28, 0x4e],
		},
		{
			"public_key" : [0x4e, 0x6, 0xc, 0xe1, 0xc, 0xeb, 0xf0, 0x95, 0x9, 0x87, 0x16, 0xc8, 0x66, 0x19, 0xeb, 0x9f, 0x7d, 0xf6, 0x65, 0x24, 0x69, 0x8b, 0xa7, 0x98, 0x8c, 0x3b, 0x90, 0x95, 0xd9, 0xf5, 0x1, 0x34],
			"secret_key" : [0x57, 0x73, 0x3f, 0x2d, 0x86, 0x96, 0x90, 0xd0, 0xd2, 0xed, 0xae, 0xc9, 0x52, 0x3d, 0xaa, 0x2d, 0xa9, 0x54, 0x45, 0xf4, 0x4f, 0x57, 0x83, 0xc1, 0xfa, 0xec, 0x6c, 0x3a, 0x98, 0x28, 0x18, 0xf3],
		},
		{
			"public_key" : [0x5c, 0x49, 0x2c, 0xba, 0x2c, 0xc8, 0x92, 0x48, 0x8a, 0x9c, 0xeb, 0x91, 0x86, 0xc2, 0xaa, 0xc2, 0x2f, 0x1, 0x5b, 0xf3, 0xef, 0x8d, 0x3e, 0xcc, 0x9c, 0x41, 0x76, 0x97, 0x62, 0x61, 0xaa, 0xb1],
			"secret_key" : [0x67, 0x97, 0xc2, 0xe7, 0xdc, 0x92, 0xcc, 0xbe, 0x7c, 0x5, 0x6b, 0xec, 0x35, 0xa, 0xb6, 0xd3, 0xbd, 0x2a, 0x2c, 0x6b, 0xc5, 0xa8, 0x7, 0xbb, 0xca, 0xe1, 0xf6, 0xc2, 0xaf, 0x80, 0x36, 0x44],
		},
		{
			"public_key" : [0xea, 0x33, 0x34, 0x92, 0x96, 0x5, 0x5a, 0x4e, 0x8b, 0x19, 0x2e, 0x3c, 0x23, 0xc5, 0xf4, 0xc8, 0x44, 0x28, 0x2a, 0x3b, 0xfc, 0x19, 0xec, 0xc9, 0xdc, 0x64, 0x6a, 0x42, 0xc3, 0x8d, 0xc2, 0x48],
			"secret_key" : [0x2c, 0x75, 0xd8, 0x51, 0x42, 0xec, 0xad, 0x3e, 0x69, 0x44, 0x70, 0x4, 0x54, 0xc, 0x1c, 0x23, 0x54, 0x8f, 0xc8, 0xf4, 0x86, 0x25, 0x1b, 0x8a, 0x19, 0x46, 0x3f, 0x3d, 0xf6, 0xf8, 0xac, 0x61],
		},
		{
			"public_key" : [0x4f, 0x29, 0x79, 0xb1, 0xec, 0x86, 0x19, 0xe4, 0x5c, 0xa, 0xb, 0x2b, 0x52, 0x9, 0x34, 0x54, 0x1a, 0xb9, 0x44, 0x7, 0xb6, 0x4d, 0x19, 0xa, 0x76, 0xf3, 0x23, 0x14, 0xef, 0xe1, 0x84, 0xe7],
			"secret_key" : [0xf7, 0xca, 0xe1, 0x8d, 0x8d, 0x36, 0xa7, 0xf5, 0x61, 0x17, 0xb8, 0xb7, 0xe, 0x25, 0x52, 0x27, 0x7f, 0xfc, 0x99, 0xdf, 0x87, 0x56, 0xb5, 0xe1, 0x38, 0xbf, 0x63, 0x68, 0xbc, 0x87, 0xf7, 0x4c],
		},
		{
			"public_key" : [0xf5, 0xd8, 0xa9, 0x27, 0x90, 0x1d, 0x4f, 0xa4, 0x24, 0x90, 0x86, 0xb7, 0xff, 0xec, 0x24, 0xf5, 0x29, 0x7d, 0x80, 0x11, 0x8e, 0x4a, 0xc9, 0xd3, 0xfc, 0x9a, 0x82, 0x37, 0x95, 0x1e, 0x3b, 0x7f],
			"secret_key" : [0x3c, 0x23, 0x5e, 0xdc, 0x2, 0xf9, 0x11, 0x56, 0x41, 0xdb, 0xf5, 0x16, 0xd5, 0xde, 0x8a, 0x73, 0x5d, 0x6e, 0x53, 0xe2, 0x2a, 0xa2, 0xac, 0x14, 0x36, 0x56, 0x4, 0x5f, 0xf2, 0xe9, 0x52, 0x49],
		}
	],
	"stream_xor" : [
		# testVectors was taken from set 6 of the ECRYPT test vectors:
		# http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/salsa20/full/verified.test-vectors?logsort=rev&rev=210&view=markup
		{
			"key" : [0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x78, 0x73, 0x61, 0x6c, 0x73, 0x61, 0x32, 0x30],
			"nonce" : [0x32, 0x34, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x78, 0x73, 0x61, 0x6c, 0x73, 0x61],
			"message" : [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21]
		},
		{
			"key" : [0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x78, 0x73, 0x61, 0x6c, 0x73, 0x61, 0x32, 0x30],
			"nonce" : [0x32, 0x34, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x78, 0x73, 0x61, 0x6c, 0x73, 0x61],
			"message" : [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
		}
	],
	"sha512" : [],
	"poly1305" : [],
	"hmac" : [],
	"ed25519" : [],
	"aes_cbc" : []
}