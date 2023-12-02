use super::poseidon_params::PoseidonParams;

use crate::fields::vesta::FpVesta;
use crate::fields::utils::from_hex;

use lazy_static::lazy_static;
use std::sync::Arc;

type Scalar = FpVesta;

lazy_static! {
    pub static ref MDS3: Vec<Vec<Scalar>> = vec![
    vec![from_hex("0x30073483101dd177bd0812b4ca4bcedee48345e33de7a5a6981f57f1278ac9d0"),
    from_hex("0x3530d7fc3f7fdb03819484411ae7c81acfd168fafa93584f642b39061e1367d5"),
    from_hex("0x1a1e827d5059826e73b0a223b2f11bf90f160748138089ce446f044a14f088b8"),
    ],
    vec![from_hex("0x17968b2dba5022717252774e0b0a5374b9faa426cef154dffbec51aea6d00479"),
    from_hex("0x193c87b7496415abc28a0f4d03e67b7641e29511cb1d712018e6c025557870a9"),
    from_hex("0x2906185563777851a8e9e1424ee77afba244b61e15671d9f56c0543f3ef4e744"),
    ],
    vec![from_hex("0x2b3a83b127821294bae6082c3f834dc1bfb68b95e96ea9cf6ef15ba1615edb20"),
    from_hex("0x3192c98e28cb9b08cf845ffe109cd7a0fd28a984117b4ded34ce228d62d2158f"),
    from_hex("0x0d31cefd09706f885e61bbb2024696deb33a27b9b23019dd00fdf899875734ac"),
    ],
    ];

    pub static ref RC3: Vec<Vec<Scalar>> = vec![
    vec![from_hex("0x21512346b8ece60d5951c1505089c2b4220707ca56373bb9d828fa33bbfd2a31"),
    from_hex("0x2b3a40252c69e83e92c548e199bbbeba4291e0d7fc3b4810193606753da588c8"),
    from_hex("0x2a1a778e3f303c4187c082ea4475734596fb10bd2954843e12be80e8c1c0d464"),
    ],
    vec![from_hex("0x224d2355fc17ee0b5e46455d2ef3a85cfaa88b08689b0d0e4c111094fd780093"),
    from_hex("0x2241de16388cdd7ffda42e0838b5d59bc2182f14bbef622fa633d8b87250a740"),
    from_hex("0x325f11e96905193f6836e6fa2c727dd0261ea083fedde9873f1e7b9d90419833"),
    ],
    vec![from_hex("0x1cc541b9ed19280c216f6b90876cbe83d07ba14fcc6f2af068e1dda739f5acb9"),
    from_hex("0x0f6f3f6703c0dcd136b24ddb8766fbcd69bbc9cb3bb20a1da2f7130c4ba62664"),
    from_hex("0x352376600a75802c6e6c6da69001e0376328848bc7ada465176d571ba029a20b"),
    ],
    vec![from_hex("0x2b1708d59adc4ba04a6bcb2dd264c1b014e0b7bae9bb3af916eb276ee3a34565"),
    from_hex("0x161c8a77adcd1a5f8dad71c3b044ce64bab9de792195da91a0b0acca4f8b4568"),
    from_hex("0x1d53e37d6ddf6dd88beb25c0870b2d0af2a51efb6ada05c4ac7e5099a71499e0"),
    ],
    vec![from_hex("0x0b6d7adb7b72cfaee0184354accbff821a14efb48b46405b397c037a5e15f095"),
    from_hex("0x2444c70bc898765b95c5438156c28671cfd20569a8d31b3f08cfa60d2bb18d6e"),
    from_hex("0x1eca31224b0d4ae965b179fd952d958de48a5de147348ca5dd00790d5c76fb2f"),
    ],
    vec![from_hex("0x0c3f882f7a3bd8ae1eb328e026f6419db30a5026c279df1219499333ef8caa06"),
    from_hex("0x38011264a16e7cf3e96f029dbfe344e778314b1e2e9d8a2f8f8f76ff5795430d"),
    from_hex("0x3119da354a6f450bf8f700b89b8319a6f57d6278bfb0bbf9d8e37d55c9f3133d"),
    ],
    vec![from_hex("0x0bbe0649314a68a31d5e8222bfec7b1298fc5bc1e6ea098675c94695aa3aa221"),
    from_hex("0x2238971cffd7a12e565e591c0b28c8e76a4582d57892d3db5c8be394a60ba3e9"),
    from_hex("0x1badbb1e2e9734afa09ff6c92e98038b9e329e0c5d0bac9a7d7996392f5caf78"),
    ],
    vec![from_hex("0x37dbb6c5059651ae1362eba3195c08716dab6a61ce8476b5cebd09274a53413c"),
    from_hex("0x3ca22f38e795e433ae9a8d2d5f1d535bbe1a3c3fdadcd549a718e72cd257bb09"),
    from_hex("0x0854ff209558742b8d9b0cbe9db7767f33668f1f8888458bc954025ffe84b7da"),
    ],
    vec![from_hex("0x377699a38c21b41939a5098a8202ed55b4d3472e01f185f4336f4c6c879051ad"),
    from_hex("0x3492b7170200764635922920ad5e3c8761fbbcbaeaa2fc08a59f9ddac49a59ed"),
    from_hex("0x372c88a6b45c1593f353789be4cdce85dd2ea1adfca9d8444c83b7a990921a25"),
    ],
    vec![from_hex("0x3d0996734441d7d414e14d72e46eb6cb3d403a822ce642357e1319d169f4ce6f"),
    from_hex("0x026362f8c8a86b5afadc22b1cc0aa53e9da137607812778e47d5f86740722a52"),
    from_hex("0x195b6294bdf65bb0c07569f6c6193de7e5e9ea5b17b5adc39179ff15280fda29"),
    ],
    vec![from_hex("0x11dfbb5f5e48ea973c6ef2ece89463c5316bc767896b67b88be18a1d858d6f52"),
    from_hex("0x071180314ab2e242cc0552b728495b97e0c2e073970a264c43397356d6ef6c99"),
    from_hex("0x13c1cc0a221c29fde3183f7dc644004d3f4dd341fe7626996ce68c69d73204c5"),
    ],
    vec![from_hex("0x06fc0f5f038d0ab20f4815ba721b366824bf534980265836b224fecfccb6fcaf"),
    from_hex("0x122e97658c701fcb7b25d8ce0629f2942dd8f07d6ac06a91320a6f1f4421fd59"),
    from_hex("0x3a19573d57741adba1942d72016391d115a1971af158cfe2a776cb506d714272"),
    ],
    vec![from_hex("0x3b34dfdced639990194ad27c8d3bebd9e6657350c0c522a2b65f2ace44dd16cf"),
    from_hex("0x2d39cfe678f0816cf3bc7a0476517c070d9db6b0f20aa849fc9746e4be5bdf80"),
    from_hex("0x1c2e919d0e061629fd6b5416898dc1d5a5cd0e130531151d18480906ea3d9cc5"),
    ],
    vec![from_hex("0x3dae30c784fd66c4a551a6b0a9551747fc1cae54522bb25238f06a7a3e4490cb"),
    from_hex("0x0264c23f67c44aa792f1c731655e1c9eefc4b4b808913f6bb3806ee56caf9c8b"),
    from_hex("0x0fa6d7c32c55e7621d72604c5abc1d970e7569dbf1475f989816be1ac248f889"),
    ],
    vec![from_hex("0x2516928d25d3fe4ca89ff71d5958f4f256d86457b58215dc8c1b02454314ff19"),
    from_hex("0x10842e1683519bc44c3b3de92cf860e9185c5ed67b20662ae8c4f50008de4780"),
    from_hex("0x036c65d30abc46a63c4b26ea1e17c5325181354f800fa4c4f207ed1849bb8b3c"),
    ],
    vec![from_hex("0x1577e14026128fcbe30d7fe646e0cfcf5a91052f2cadc41553e10aa4ea94eb81"),
    from_hex("0x38814490cf1681f17c23adf62ea2988d48fdce37b3a2fc259b090391d72be770"),
    from_hex("0x3c24dd5b9460893f28e95b9cbaaba0e1b6af9c00d8182b66ec771ca957b4cb8d"),
    ],
    vec![from_hex("0x367180fac58037ec0d86a1932aabe6a5e353feaf64b1acaaf208a79f711fe35f"),
    from_hex("0x28ad8a1ecc6d58bf0cbff23e654b824abecae09905278fffa65e9b0d634d9205"),
    from_hex("0x046fe9ca53b25a411a48d539b09984e2e04bbfe5bfdbb3d390e7489c2cecc4bf"),
    ],
    vec![from_hex("0x1b6869c3d4333173de4546f09cee0dea3ae707dfa5e1bcebf9d7671cf766aac0"),
    from_hex("0x1ac8cb354ad46130e09e72c559d322a6daf108002e5f1040c0db23e21ba7b12d"),
    from_hex("0x16ff5289ab75696ff12f1a2207ee96d0824574cedc0bb3558f4a6ae6e674c446"),
    ],
    vec![from_hex("0x3b7f271e38ba8cde9b5fabbe82eae1b848b78a32022516d4cfa423062a3632a1"),
    from_hex("0x23c4be170342843749dac4e883d34ef66ac377a41c53edfa136f0ba50d0fe5a3"),
    from_hex("0x366862ca8fd49db9b624d9a1e33b393cf761a181813955f48ff1d8d16d7d7d73"),
    ],
    vec![from_hex("0x2b12d66066df3e3446f8fcc6bc74aeb1dadb4f06f5d1b49646c52708c447cd14"),
    from_hex("0x0a88d5bde48f9b752b856a2646a793cf285473c38870624240b143758c0b5289"),
    from_hex("0x1cfea95345ce89e544d0447eb5a655610588ac2097f3008389897701d404c98f"),
    ],
    vec![from_hex("0x3a9ec343c1c6a122f3897126da51f92d0187ce6e0221cb23bb1797fe4ba72e1d"),
    from_hex("0x3bf940ada3cf20415d3b0b12dc1e0ecededea4dc1e5d7d1587edb6b4c79342f6"),
    from_hex("0x008621ee09a0ef69dee34dcea9261a2adfa38e8304e461a9635bf49c0f36d4be"),
    ],
    vec![from_hex("0x209cd0df3e50c56186a5db349b595bad4395036a310c098ecea3d041576725fd"),
    from_hex("0x25b9a4649aa7d962e12ba088d37d5b582f5f5c160c8d28c03294c26a52447f18"),
    from_hex("0x05ec12eb5698ef5afe1a8e225a299afc37b923dfb5094870f4ad979aa416fbed"),
    ],
    vec![from_hex("0x3e682fbf59f4cca0b6d50829d76c246e65b7f78d939191d570c977e4c5257d0b"),
    from_hex("0x0b850ec39f210fbf8797cd35565461378546c06a342edc84dc7831ce36614009"),
    from_hex("0x290b9a83a1cb831f478bd70ebb8930d0cc23f44443b3d1e61dd60f41b6a49274"),
    ],
    vec![from_hex("0x04bc379725cf05684871ffeed475d2d2bba63620f86306bb445ab768ba2aa185"),
    from_hex("0x2328f4080eceecfef5ccd20da1be4bcd31ae5cc77aef7ae71c51e18c59c3f1ed"),
    from_hex("0x302caec20a4e995e4ccc8565a77af10e49b3f7754b9a5967157944c30743b1bb"),
    ],
    vec![from_hex("0x10741146ca5ef1a2a085754a2ed15a71fb495875bb63c5438ee5bf9d10e8c058"),
    from_hex("0x1a371581be47518396a1748d6538e2f4ff683d3405f7f5f73d6b9c52d1b99d9d"),
    from_hex("0x049f92746cde1b4280a5d7e8da69b7eefe1a2c4905d2846a69c11f4c22e06bf8"),
    ],
    vec![from_hex("0x3b8e5dca75c3cfb9c2579fb74cae071c8dc339208ca47deec9065e78dc881ba7"),
    from_hex("0x11a05a9592274f3cfd9b83b849c774f3c53dd187a65fdd807765337ffdb6ebbe"),
    from_hex("0x32d4144bd5e6a92072e23ab63c252bf1bdcff45c185f2b14bec92202465278b4"),
    ],
    vec![from_hex("0x3d8a49dc1f8ff51cb94645a994a818a1483f37fe38c0a863610ae6d1f59f4566"),
    from_hex("0x399070ea6f6b8ec5569408200d7e3c9f1935e00ac893af9a766efb21166bfe36"),
    from_hex("0x3242e136a19a866cc85712dcf62918bce13bdda1dfe67c24a4cabf36e365bc0a"),
    ],
    vec![from_hex("0x0f46bb63560d481ebfe015bc67dd4e51bb7463ddc546d3d436e5cb688bde224d"),
    from_hex("0x0fcac22e2ed86b92c2bce7a64d6fe20785f8a64fc3cd44b7791798d6ffd2cb5f"),
    from_hex("0x0db2a01d98799909617028dbbcd9ca49a27accfd4b5aaaf03050d78ae0c4e707"),
    ],
    vec![from_hex("0x343c446f363b07a7baf45a6fa516f2f5234c9da12da24c5c950ecf9d3698cffd"),
    from_hex("0x35520e3e9547534a00c2ef16d42ae1fbb4f63896a4e261f571f2071ff0a434e8"),
    from_hex("0x18e2bc16686fde3f4d65ab127982160400583faec949be8a14c0be267273e24e"),
    ],
    vec![from_hex("0x1a9d7fdef949af9f8f4d7be3d6df2fb11fbcfa26bfdc1ea7eb9dec8a5b018f09"),
    from_hex("0x0e6dde8951c3906c528a73f7390da5a327c51bee762e85a649794366139967fb"),
    from_hex("0x1224677711f1c8c1e7bf1cba520c187a6b0ce732fd15fec589a191ba2531e924"),
    ],
    vec![from_hex("0x00923f9b8d8bf4e6da72c660dcf6c73323ab8464c1be4165d7f9c825b6e378da"),
    from_hex("0x3121dbf9153b81e93bafe8f7fbdbe1ca51d08ab1954e1d81e103727126c9f997"),
    from_hex("0x32bdfa8034123b28726459bf81a351107bb51072303742efac53c5fdf86a7259"),
    ],
    vec![from_hex("0x39fc1a25f3aa12efcc435280b2661c3d86a3f3c7c23648ea11e43b22c0e2e5cc"),
    from_hex("0x37eaa43631c3bd82683a32d73e7776604fd3c46f9d0cbeac6cd0e71ce7c3c5c7"),
    from_hex("0x12cde892a12a2ad78f3eb3031e103ddc74329294cf77b60e4ba15af6f0604b75"),
    ],
    vec![from_hex("0x19205f51def8e3d739cde771d326347828b25da3abcb32f4b1e42fe327eadba9"),
    from_hex("0x38e671a88e7ea69a5336d12d7b5aae8f58e651fb75e039d8bc265931375bd3fa"),
    from_hex("0x04a0c66f211944ad4bc0697282167fb11c64c47702338f089ea114342a55b78b"),
    ],
    vec![from_hex("0x05ecdec57657e13785f7ad36a1ffa3fb2a14f77f8926f380c995c8cccb4615e0"),
    from_hex("0x0caaab97b61470d5520bb52c6d80db0eeff0466570135b548e10be1908e21628"),
    from_hex("0x313dca349c300fc98ee07d5632d2a933db15f4ec42d4dff331a1b63b73956726"),
    ],
    vec![from_hex("0x2ba53c3c516996e4916af3b5382b329d23332b1d06d70e3c29a39195e2a777a6"),
    from_hex("0x0a90bc8fb0098bd2f28105fac82c67e79e0937cc6173f4620a8e452548c08caa"),
    from_hex("0x0937d48aea070a92fb4e6e6109c1c9f3b48076b96c1ea1ab1be00da1153c08ae"),
    ],
    vec![from_hex("0x3f0e62be22dc88bc9bfa2ea479e1106c72347fe7b690ffdf9c3b315ec9774561"),
    from_hex("0x15f84c77fd056ca65029aabaa9f89c30457038625e2acbd907748c1a1407dc98"),
    from_hex("0x3ffa267d7075b5e569e74351c9ae79bae3366a389a39a03c1306f34f5f782af0"),
    ],
    vec![from_hex("0x1a63c024e9499276f257305343bd414e61680ec19e2875f61fcc4826ed37f2ca"),
    from_hex("0x149244a452669510aaa0313870302b2ab2358efd3a0d677822b540de99f71df9"),
    from_hex("0x20f8656afdf2dabd445deca1acb01b48dec203fab738d0d4e72f2e17b4b36476"),
    ],
    vec![from_hex("0x181ab5b402f3a6b369641e4a0fce79af06ee1903bc21d3d65ebaeb12252752a7"),
    from_hex("0x1c6bd7a9bc3ff680213a81bdb8c1face289e0c03ea94fa5c85a44eb39ef74686"),
    from_hex("0x1c51955a943fdabc332bedd4bf233c9212aa14862a743a332b131dd62dca9315"),
    ],
    vec![from_hex("0x1c20514c7031d9f7905657e941b4b383c78be92ed79b3f2719280cc4e75588c8"),
    from_hex("0x1adc7f31b027151581deaf16af2b4ff63f3cd799280c8df8afadbb5296759cbf"),
    from_hex("0x1724525f10f4c2427de1c50c7958e6c9025d2050e338c25e69b0fdddc47223f2"),
    ],
    vec![from_hex("0x36823d305483f52cbebbe1849d395e868d5baea2988e4024d44acd16b67fe0f7"),
    from_hex("0x285342bd16b96a9a380deffd347f3a4dbd9f8d6fdbf9a57b658f6b25cd22a0f9"),
    from_hex("0x1a40a8d28f86a6f529cea2203a0dd140404f40fc57cb733d5144bede73ab2c09"),
    ],
    vec![from_hex("0x0ac11b4d07808a47ddc422ceb64729823d6dc0408517c37239c8f49d4a2705b4"),
    from_hex("0x388eda0bd95f234ca0c82d5397d3201e0258fa8e4f8b53b8efe89a9eae4671fd"),
    from_hex("0x3d0092de09764466e5f76e44fd483682308624abc0f3076f704fd5bbd85882b1"),
    ],
    vec![from_hex("0x11fab3bb290502127c9bd893038d972382a3a18c4ba85f82585ba54f6609cadb"),
    from_hex("0x353b7245b9a556d652edb91992a8dd8a7f43889482df44ecded9927bd8124f32"),
    from_hex("0x0589bba0be66abf64414430429d594924cce5bd9d3ebc591b85f59fb09ab5dd7"),
    ],
    vec![from_hex("0x07c14c341bca58281a258db8067a487a917f570e00f451fc912d21d0413e922b"),
    from_hex("0x16a2c60433e264e43b615638020578e04a3e333a6f68837abbbfa5e6a47f220d"),
    from_hex("0x33d9e47853a0f2a6992e8223c0f6518d29fcbd540b650b63c5223686a822b234"),
    ],
    vec![from_hex("0x0c2cf358ea7363ea144587d3652f3144a74dc6c7f723a6ee2fc398aaa66db2d2"),
    from_hex("0x39d1e6d75c580b1bac29360206470e02e975a8b9f011ff10d5dd55bedb289e51"),
    from_hex("0x0ae4f2bf6600d8c9dce8a8ee44df1b443ad3443ac1594ee2c23f1a8bf6aae26b"),
    ],
    vec![from_hex("0x3b389e83e83ccb6f4b87183e75cf5894a6e6bb4ecfa3cc4321a7fe0184dd9985"),
    from_hex("0x380cc98790c6d5394220905f05ab4dafff7fdb5516b1754ff0feac9e5c848460"),
    from_hex("0x151882cd1d662381341a7621d9f85ab38f0a75939070c2d1a0600135ea19d8b9"),
    ],
    vec![from_hex("0x1d82462abe46617be0d9702f9d4a38258ae72fad00e3a720e0c5fd02abf3b387"),
    from_hex("0x0f14c20b6de2f6901c39e2bd801d84b25c3232b4e563b9b589c0f5a503018ef1"),
    from_hex("0x21ca5c74f16b9f33b128978493e8c1f32cbccc48a5472b255c8ae51f1b2c5cf5"),
    ],
    vec![from_hex("0x3d59a6e9e5f8d49ceaf2d9a9bf74d1e73fc9d80d7b3ddd216c90733ff2b046a9"),
    from_hex("0x0db32d9d9938475efae1b47d9e4345864376d8ce1f2368056912fd6cc1a5457c"),
    from_hex("0x2c8c795f805d4421526b6b36944192d959ef9c1c24540f85d4a2a5ee16392685"),
    ],
    vec![from_hex("0x3467b3994d4e344f8f5680680b9ffe2affcc13a2c033f08c450180e09a19fd65"),
    from_hex("0x29e8231e2262be0512d87513a09f0b8fef8532d3c6bc740d66f17c3ea075c345"),
    from_hex("0x34424bf30fa49002d07046482d2201cdd2f851261248b0c5f8ccc232ef1da29d"),
    ],
    vec![from_hex("0x376318402678c5926d4a7e7a21c9ae8cd9a6b1de873485ca6396492e68774302"),
    from_hex("0x307566c786b878f0f7ed1d5bb1aafe322f022ae43790702ea6fdcdd22b03cd24"),
    from_hex("0x343c1414df47ce2ad7d2209d8431712988c1b157393d8d7ae75f554b81f93a0a"),
    ],
    vec![from_hex("0x3d36f4aef7a7cd3b1607c39beb565d80dd38294b12ce648e96514a4486db53c0"),
    from_hex("0x1d3a85787e45822c91269cacfa5d0e3d10af4d6c2683c3a41ad5b3e223d94449"),
    from_hex("0x2a6fc367c12c0622e44d0cffe8e8232eca69cdfab386e68635236dfcd5d459fe"),
    ],
    vec![from_hex("0x031ab82c9a6123a6ed60c330e5e8006788e3a55da177285050dc2a8246dd1809"),
    from_hex("0x2227b96ea6cbd1674bed1d0007e01ec08a559784b95794285084cef3e6734f4e"),
    from_hex("0x0e8d7e1fc394f283375a899b34a9b37a43fc28f9bec9eb99be8fd2145979e1c8"),
    ],
    vec![from_hex("0x007fc35401b8b3e36a9245dcc5e0411c7758c70e58669c860a945ea4fdd07696"),
    from_hex("0x30b9ac5b60e480809919d882d94449d651fc10a03cefc7f4e7943c78836f9ab1"),
    from_hex("0x249486c0c6406c895a8cc4f299acf0fe10cb3cb70feece6ea792218b8812d93c"),
    ],
    vec![from_hex("0x3db4c586b783c121ac523a02a364a31a6f95c58982cd631b42a695112b72cbf5"),
    from_hex("0x17c4305989fba2d8d95a75657b26523a135a38403093708b61ae2a462ea11205"),
    from_hex("0x390b10a6d0fdaaa51e632e6f9c0ad19491d171a77142eeba3de6dfbb0236a7ad"),
    ],
    vec![from_hex("0x2f7c80cfc5ad2d1dc9dadf1023682a41f11413403fd417615203428afd650128"),
    from_hex("0x3fa4e843af0b91128d62955dda2ccfb7f40db9b0865de4aeff3d4d8a0bc584a7"),
    from_hex("0x01d8cd955e5bb2d2aaa89fa97377b877c2a40dc9a79d1201e6c5d53ce82bf12a"),
    ],
    vec![from_hex("0x123e6e1df8b9599f5f781ee9b1b92e29432a0961418cbb42dd92789de0cc55ab"),
    from_hex("0x3db03520ec3aef4257c5e271d30097eaf8e54f569ea2a9f28ce8e61832c67fd9"),
    from_hex("0x35dae5ec99859906f27922d5c28310165177af321376651f3f4379485dbf36f3"),
    ],
    vec![from_hex("0x141af4761654e69799e6ff9a92384e427f0c8fd79b6a68e2cd50eb6f6b79ec57"),
    from_hex("0x0f4ad273f8f60818ff5d808367e2d11dbf7e96c0229ccbc7e5b8c1317c1675bd"),
    from_hex("0x206d4fb1decef5a3886dd148559c94670746dc15f346726811d875476b7fc6e1"),
    ],
    vec![from_hex("0x21d31cd4d9c2dfcf67b847ab8a5bc7923e09ae66f08ffe7aa70443637edbf30e"),
    from_hex("0x2c9b66734476906935f73b69f1b321b2cd0cc756a0e76a9a0b315d9db3d1b7ad"),
    from_hex("0x1ecdc0247e585ae987375df5e172123e92a6f8ff71436e2ecdb82ada41942194"),
    ],
    vec![from_hex("0x212f7278b3c0cf93a97d52435ab7359f73b66fea92c7743fcdc2fd4653da2a07"),
    from_hex("0x379e42c19c376122e5f1590ceb24a221840adc7763aea8e93a99fe27400314b9"),
    from_hex("0x2f357ba06f7bd7822797a8879e326e033e42714e84b84c1334edaafdff3d6280"),
    ],
    vec![from_hex("0x223d6c2a250d159bfc5dfbacdcd37020271a12833d42090cc43163ef8cac7ec4"),
    from_hex("0x11a6d6112f26784b31ad06f1f8bf8ae1281f1d04ca64e3bc387dcd05d8bc809f"),
    from_hex("0x31d8e18e44c744381e68bccc797464017ea3510615e617c7a363e29108851d69"),
    ],
    vec![from_hex("0x27fcc6e060cf62a2465e36b752d90c9b162ae2bba26d2f58bdcbdbb62b1e5c0e"),
    from_hex("0x283810f3db7207faaafd6b1ade54c91a215da5f29acc22fb6db3b2d132e92580"),
    from_hex("0x232a2898c1aed25feadb5bc4977233585ddfa058afc52109350dd80eb351c07d"),
    ],
    vec![from_hex("0x3925a95baecde32ba2c23536fd93d3c329ec2e19b46874876083fb677aa050a9"),
    from_hex("0x0dbaf0853320c3036678491bf7b7c60d16a23e062a8fc836bb3753b9f6b9e04f"),
    from_hex("0x3f69e46b36699d66f89757f9b084a723f821aa15c69e58e7a5ccfe1c9dac8323"),
    ],
    vec![from_hex("0x10cce8dbb18beecc2ded4cde87bc2d1dff4ebd816fd82a5722d93d10b3486fee"),
    from_hex("0x37c61ce90fd1421afc2c7fadd963f0c57aa68ddb18fb6885fbdb237738250737"),
    from_hex("0x06bf2f6aad10d4c96fbffa34f68cf21ea05a42c85dbd2220f5fff88bf27be629"),
    ],
    vec![from_hex("0x267c54cc141b8a2e7d4aefdd4bddd23891904897fbc4fecfe4b40d780a5b09a2"),
    from_hex("0x34fa47815fdd4e079876d0242f8ebb5cf865c6c623daa35772e4316f950eb11b"),
    from_hex("0x2bd08eb923d8ac5ccddb4e358005268673c89fcf18b78559b36d07c25bb73cef"),
    ],
    vec![from_hex("0x14762e17a0a72ffe82c82d5ebfd3994c43787c441d588c12701c4e9893908fb3"),
    from_hex("0x2876d1bb0520c704eabd40c32b854076d3edc44253234acb1a5459fb57481b03"),
    from_hex("0x187111914378033a4f9e7b1b72bbc5bbdf1e1b2050617de92b0847b9161bd124"),
    ],
    ];

    pub static ref POSEIDON_VESTA_PARAMS: Arc<PoseidonParams<Scalar>> = Arc::new(PoseidonParams::new(
        3, 5, 8, 56, &MDS3, &RC3
    ));
}
