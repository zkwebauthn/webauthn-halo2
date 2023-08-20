// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Counter.sol";
import "../src/core/EntryPoint.sol";
import "../src/P256Account.sol";
import "../src/P256AccountFactory.sol";
import {UserOperation} from "../src/interfaces/UserOperation.sol";
import "../src/SponsorPaymaster.sol";

/**
 * @title CounterTest
 * @author richard@fun.xyz
 * @notice This is a sanity test for the account function.
 * We want to be able to send a userOp through the entrypoint and have it execute
 */
contract P256AccountTest is Test {
    Counter public counter;
    EntryPoint public entryPoint;
    P256AccountFactory public accountFactory;
    P256Account public account;
    SponsorPaymaster public paymaster;
    address snarkVerifier;

    // -------------------- 🧑‍🍼 Account Creation Constants 🧑‍🍼 --------------------
    bytes constant publicKey = "iliketturtles";
    bytes32 constant salt = keccak256("iwanttoberichardwhenigrowup");
    address richard = makeAddr("richard"); // Funder

    /**
     * Helper function to deploy raw EVM bytecode.
     */
    function _deployBytecode(
        bytes memory code
    ) internal returns (address deployedAddress) {
        assembly {
            deployedAddress := create(0, add(code, 0x20), mload(code))
        }
    }

    /**
     * Helper function to create UserOp
     */
    function _createUserOp(
        bytes memory callData,
        bytes memory paymasterAndData,
        bytes memory signature
    ) internal view returns (UserOperation memory userOp) {
        userOp = UserOperation({
            sender: address(account),
            nonce: entryPoint.getNonce(address(account), 0),
            initCode: "",
            callData: callData,
            callGasLimit: 10_000_000,
            verificationGasLimit: 10_000_000,
            preVerificationGas: 1_000_000,
            maxFeePerGas: 10_000_000,
            maxPriorityFeePerGas: 10_000_000,
            paymasterAndData: paymasterAndData,
            signature: signature
            // signature is the calldata to the P256 SNARK verifier
        });
    }

    /**
     * Deploy the Entrypoint, AccountFactory, and a single account
     * Deposit eth into the entrypoint on behalf of the account to pay for gas
     */
    function setUp() public {
        snarkVerifier = _deployBytecode(snarkVerifierBytecode);
        counter = new Counter();
        entryPoint = new EntryPoint();
        accountFactory = new P256AccountFactory(entryPoint, snarkVerifier);
        account = accountFactory.createAccount(publicKey);
        vm.deal(richard, 1e50);
        vm.startPrank(richard);
        paymaster = new SponsorPaymaster(entryPoint);
    }

    /**
     * Check the account was created correctly with the correct parameters
     */
    function testCreation() public {
        assertEq(account.getNonce(), 0);
        assertEq(account.publicKey(), publicKey);
    }

    /**
     * Create a userOp that increments the counter and send it through the entrypoint
     */
    function testUserOpWithPaymaster() public {
        paymaster.deposit{value: 1 ether}();
        assertEq(counter.number(), 0);
        bytes memory incrementCounterCallData = abi.encodeWithSelector(
            account.execute.selector,
            address(counter),
            0,
            abi.encodeWithSelector(counter.increment.selector)
        );
        UserOperation[] memory userOps = new UserOperation[](1);
        bytes memory paymasterAndData = abi.encodePacked(paymaster);
        userOps[0] = _createUserOp(
            incrementCounterCallData,
            paymasterAndData,
            validSignature
        );
        entryPoint.handleOps(userOps, payable(richard));
        assertEq(counter.number(), 1);
    }

    /**
     * Create a userOp that increments the counter and send it through the entrypoint
     */
    function testUserOpWithPaymasterNoDeposit() public {
        assertEq(counter.number(), 0);
        bytes memory incrementCounterCallData = abi.encodeWithSelector(
            account.execute.selector,
            address(counter),
            0,
            abi.encodeWithSelector(counter.increment.selector)
        );
        UserOperation[] memory userOps = new UserOperation[](1);
        bytes memory paymasterAndData = abi.encodePacked(paymaster);
        userOps[0] = _createUserOp(
            incrementCounterCallData,
            paymasterAndData,
            validSignature
        );
        vm.expectRevert();
        entryPoint.handleOps(userOps, payable(richard));
    }

    bytes validSignature =
        hex"29f998a79ad54d561f202d10c32031f607f7fa931b77f5cbf89b38076592be9a0895aa5203308541af5b2e0dc22bef9cec3ad08e4d9c9b1bbef7324df6fe45a81115c7b29d8cffe93b17927d06bd9487f341ceae76d61c23acdfda419065e6352c4795e2b426fdfd9249004b4aa2e64c677788ef2188e67a6732983ad5da2c462628d45d3a082a46f41ed0c6a2dde9bdaab5983bf2869f25b21afe2e4c2110390d60b846f86cd6ee2483995f1ccc8618eb9009c1239a954d5d8e07394f98934829ec28d4bfded92e01afc92c3beb0461742d38123f175998b6bd80e96bb2cd210bf330f9d106ccff8e4ecd9ae2efe546ef2bd7a4c0a43af444591399e5cd7dea0ddbec375fa3bd57180f1474856c330844b99beb8bbfd2f7b667e679374af30c280832199f21e17a27a23ad86399b7c715770307db342b6c19523610c48248692e145515fa73e001aa804fae90f8363c5a3c80e4a7bd717d6f08e0bea701283028eae1bbdd2c195d5c538eaad1f827ecade6e4b2d04a602c03f9048b0e9378bd1d9dd34ec7cd389f6066ca7e29b60ff6c223a77f5e285b22759ee83a2474c88b2402e45816b14132c60b9463f9f2fe743c1c368a47615c3f770fd656e8fdfc762bf17128729f6efb5bd05c666cb2e3bbf2598797c9a451679cdcb3f02594756e08633ef9fa3b36412b29765b96191e4006350af9e136997e14f9a89b632094e71d1e68ceccfa8d5ecf9b9446ffd1aff91168f78b192b9c12bbc23d5e0474105613f45aec77260bfe5637dd2eb1eaabcf0e92c317940a3ddbd6d50e67ada8f67e185e8b698d53b352d0a64e10404fe44b9a85b1898ac4712a389224029734a11a1d362d976d6bda11fd56ac84827c660077e2f893bf7a2b18a0217087642ed4690d26b838a549e1940455aa2627f171864bc7083dc5673b06f17fb9147840867b06c33f55e2a42aa487cb5b0604b509246ff8f68978ac8b66c55b661f4a45d0e00fba845525372b874cea2767e431fe03dd36c2af563bf94cb9ecd0d2dc48dc2a200b151295886090d20b567806f7c6e3c2b4147d44cf395c8766a4cc3ddc52d5245368fe43088cbd2f574b24d9fcd9d2ed519efa83a7958296dbd91629b11a3703b7ab2d0b8223d7128edd8043e85661d8928b5929fd18da11d54c5c515868c32fe40d3bb45e2967dc616df4fd3fef2c3f72c13f5eb7d8516c43d604b1d5cf2224a177344796b41eeeab8cca7c1f182b66e1025efaa76f88a406fee98ea8e9392d54b900e3c158fca9bdc5498d1ccfc8873d5f61b648c73145961b3a16390e860e1bb2fe95e5e2a92fe74f35317bd2a64da8c52a1a9eb807ca689a270517dd320f74e37dfcf3c9e8b785a77457a01df6bb626ccbec32b6ad193fdc8ec7a3a9bb105eb0d726d6293ac555ffb339760f8660c6f9e8480c565e7324933015d7d3c70746939df0f749ffeb12087425c26975ca212b507610c83e490d6e583d7869991ddda9931e6d508f8232eb650b8847930c8851e3912dff5b1d1605d7e3c1e8322d5d99670916c19d6597aa80b91e0ef2371745cd31cc42b13fcfa562ff30397f2aeed2c175358b657a721c17de12bedb350d58683001fc330afeea155488248919c857f0d216cd3d05662f79d42bfb63f93441eee1a07ba7b0058fa20b9e0d232e8398eb0b0454cafbd2fa501797cc43a05fb25609e4c2e86e6a5f5dff40e17512fa1f8db6235c1f2a35c3b87b62b4fa54d598f9fda14493cc290972ce9f90531a0b90534f982fe696408dd56474e2fc10b5eeed0939d6edb41d28bd4260f1d3047e9148a846fad8a909c64b67cf3dc0146a95f53d64dc4f7d59a799732414f118656c36ecd754a6e71b6e66ceb8367bb668a73a059d8abee5ad9f4eabf4c5592eeca4b396bb47333b7f7825d33a65134fe2d6d7d0289f9216998a321f95f2831b42eccbb297611dfcf7bb76bf54534123814b66f9acc77fed96780fef4705de2d4557333a7438b2851fe0bd7432ef1826afd39873a064788c26c05afb1f6acd23a0b37c1054d1be54c78bdd823e42c85043f91ec3c32ccd72bf08cf7fa8a47c28bdaafe20843fef3b3397428cef3794b03b9148e993b7ef8c8ee45bef6a181c27b3c2c46010595a6f6631a36b3b519f9136d4be2cd805a99f26dbdd1956ccba161c633f4e0afe17d2118364d66ded970fe925508f95eef5a8c5a2c8076128c127368f1ece7f766f49d51b179fed1fcd8690a47d03f2bd588bd826500e68cd6e1b2910465ea372f8f601e926c143137a588c5ce4d9eb5fda9bf0910eedf3d11c29ddbefd64745f8225ccc1a08be570560452552a84ef332958ec7d86641e4a652be177680396a72eee29f48b30e439ea654d319c3599166a1d593943752a232e17c170baafff14b5b775d7d0d30a3335e162a9fcc28f30f0496733ac8a73e2f2279abce417264607348b22f158eee77a26b73eacfeaf4355a2edb48a4a04a69929238960c736a57e796a5a4ac083c80e34e2cc0461b564868847a6546bc285a314503720f252764d12e0b5590e2e46b8fec06a20da5a5e8fc5e1ccbc3b2bc3ca146656b8300794597f0b87bf9d2eb422fe5513653d41323780e99a1be9a41dcb0bfb714f59e20291a8b805701f6e435cb8e73370b1253c3ec891fe4116040b0d0cd8a7ac0a6727a532cc194f5cbb9cfbfeb4d62f9b497a8b1966c18abdcfd55f1390eedd2297804cc244b25b7e393b1b8b462e502a69da1a271303a659454c5302e0aa9b3ef23e545ea521627df794bbb9ee19fdb57768a08c732ecdeb34189d2809795980d21b95a2f9d0c749100835496bf275ea7d743e4a7b8934fa4478d325de51b68af9d95d098f4540163a5be3e6c2669772f80685aff588738d5f6f7a1e8799d581605ad52efa87b498ccea2149298b0b25f49e54789fbfe1341d1e2f02c0331954b5bb5fdfccd635da25d32c7c5fce3ad1ed1985056b5f970db2471100152fe7976a1705d08e352254025f35d99b3ef397869067eaef3e1465d53c65122e2e7d3a202e7530b79bf7732447ce9068bc7fe2e251a59b590db402bcc115173a8ff64a04e2e02af6f00cfb70e4694b3f0608b85d917bedc9fb26191b49c213777ccdaee976412d326555b43335e28029b403741fc5024e23fd728485c538259eedc5b53d730ed34f8d23b27bb2a03dcf19f09fa493db193b6a3fe94938f423844733f3913b8bba732ba2456300ad72a52243c47c7d558106f42dea19032e1383abf6df27e38b2a4215ba88d1982099355cda05a2aa9e30a7da9c732902d818f04018b716975721599e11efd78e28c19ee508955c3f276edf2d58de2e3cfb2b802812ebfd3cc54cad11b78c27700cc2f184312b0aae93c16c90f51915e500109c0b4fc83f42d1d288a89b7c6c51f9fc41b258d99cc6d93b9d947df86ff9142f32c35ca02a67e9e2eebef3f467d085e03c5d47862678271075eeb8d1cbd08417b8799e11c592f947e579451f1027b3d8515d9f36236a43d6b15fbe8fbaf5820a151a0c905e61c1e6b098c99341d5ae0b24028d57567682f70faaddc936cad00f8e150818e7a3bcd46b0f51a7821e862e264f2b0cf2ac7ae791f1028ab8942526222fef01f17b71531ff140f0224378d369697df067bb7ec2e46d945273394906df43dcb812e7ea06e486de959b0bd4c7d1334010cb7be83f4c7c3cab8996072d5044c058e43f5700ba7f287d542d4a1daa7077b6496d0b6eedc129778c10b72f3737d49033de9a7b6f7272d1ad2317cb5aa706fa8649e10d723a7101d8dd74246ea0ded2552e6b85f959b9fb9425878cf17ec529a89b8af35042edb0c7e1a9";

    bytes snarkVerifierBytecode =
        hex"62000025565b60006040519050600081036200001a57606090505b818101604052919050565b6134ba620000338162000005565b816200003f82398181f3fe60017f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd477f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000161013b565b60007f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4782107f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478410808216925050507f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478384097f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478384097f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478482097f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47600382088381148086169550505050505092915050565b7f15cecfb8fa438e3f1d7bb5e3f61677b50739d2306f19cd66971e3473e1d8ca246000526000358060205260203580604052846101788284610048565b16945050506040358060605260603580608052846101968284610048565b16945050506080358060a05260a0358060c052846101b48284610048565b169450505060c0358060e05260e0358061010052846101d38284610048565b1694505050610100358061012052610120358061014052846101f58284610048565b1694505050610160600020610160526101605181810661018052806101a0525061014035806101c05261016035806101e052846102328284610048565b16945050506101803580610200526101a0358061022052846102548284610048565b169450505060a06101a02061024052610240518181066102605280610280525060016102a0536021610280206102a0526102a0518181066102c052806102e052506101c03580610300526101e0358061032052846102b28284610048565b1694505050610200358061034052610220358061036052846102d48284610048565b169450505061024035806103805261026035806103a052846102f68284610048565b169450505061028035806103c0526102a035806103e052846103188284610048565b16945050506102c03580610400526102e03580610420528461033a8284610048565b16945050506101606102e02061044052610440518181066104605280610480525061030035806104a05261032035806104c052846103788284610048565b169450505061034035806104e0526103603580610500528461039a8284610048565b16945050506103803580610520526103a0358061054052846103bc8284610048565b169450505060e061048020610560526105605181810661058052806105a05250806103c035066105c052806103e035066105e0528061040035066106005280610420350661062052806104403506610640528061046035066106605280610480350661068052806104a035066106a052806104c035066106c052806104e035066106e0528061050035066107005280610520350661072052806105403506610740528061056035066107605280610580350661078052806105a035066107a052806105c035066107c052806105e035066107e0528061060035066108005280610620350661082052806106403506610840528061066035066108605280610680350661088052806106a035066108a052806106c035066108c052806106e035066108e0528061070035066109005280610720350661092052806107403506610940528061076035066109605280610780350661098052806107a035066109a052806107c035066109c052806107e035066109e052806108003506610a0052806108203506610a2052806108403506610a4052806108603506610a6052806108803506610a8052806108a03506610aa052806108c03506610ac052806108e03506610ae052806109003506610b00526105806105a020610b2052610b2051818106610b405280610b6052506109203580610b80526109403580610ba052846105c38284610048565b16945050506109603580610bc0526109803580610be052846105e58284610048565b16945050506109a03580610c00526109c03580610c2052846106078284610048565b16945050506109e03580610c4052610a003580610c6052846106298284610048565b1694505050610a203580610c8052610a403580610ca0528461064b8284610048565b1694505050610a603580610cc052610a803580610ce0528461066d8284610048565b16945050506101a0610b6020610d0052610d0051818106610d205280610d40525080610580516105805109610d605280610d6051610d605109610d805280610d8051610d805109610da05280610da051610da05109610dc05280610dc051610dc05109610de05280610de051610de05109610e005280610e0051610e005109610e205280610e2051610e205109610e405280610e4051610e405109610e605280610e6051610e605109610e805280610e8051610e805109610ea05280610ea051610ea05109610ec05280610ec051610ec05109610ee05280610ee051610ee05109610f005280610f0051610f005109610f205280610f2051610f205109610f405280610f4051610f405109610f6052807f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000610f605108610f8052807f30643640b9f82f90e83b698e5ea6179c7c05542e859533b48b9953a2f5360801610f805109610fa052807f2ed3ad80154160493a49fb866bafcde224c1058bdf972b5520fa5689f14f5265610fa05109610fc052807f0190a0f2cbf03fe07e064a3015d18a7b0372e2bc9a22453c22e79f09feb0ad9c6105805108610fe052807f299110e6835fd73731fb3ce6de87151988da403c265467a96b9cda0d7daa72e4610fa0510961100052807f06d33d8c5dd1c8f2865508cfa2fa43439f59a80c536508e7d8451b8672558d1d610580510861102052807f1d0b6df2360495077836bf0341958613f60bd997b99e92641bdf3b9dee778c59610fa0510961104052807f1358e080ab2d0b22401986b33febd24932280eb0c01ade2d2802b9f6018873a8610580510861106052807f1f67bc4574eaef5e630a13c710221a3e3d491e59fddabaf321e56f3ca8d91624610fa0510961108052807f10fc922d6c46b0cb554631ef715f3e1eeaeac9ee7bdeb59e21fc86574726e9dd61058051086110a052807f15a9c33a6d34b8fb8e5c3ff61814ca50c878ed14bc17d9442cd5c127bf33fd6d610fa051096110c052807f1aba8b3873fce72e29f405c0696c8e0c5fbafb33bda1974d170c346c30cc029461058051086110e052807f0cf312e84f2456134e812826473d3dfb577b2bfdba762aba88b47b740472c1f0610fa0510961110052807f23713b8a920d4a1669cf1d903a441a61d0b8bc4abf4345d6bb2d7a1feb8d3e11610580510861112052807f193586da872cdeff023d6ab2263a131b4780db8878be3c3b7f8f019c06fcb0fb610fa0510961114052807f172ec7985a04c12ab612db045b474541e0b30cc000fb3455c452f3f7e9034f06610580510861116052806001610fa0510961118052807f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000061058051086111a052610fe051818161102051099050806111c052818161106051099050806111e05281816110a051099050806112005281816110e05109905080611220528181611120510990508061124052818161116051099050806112605281816111a05109905080611280528181610f8051099050806112a0525060206112e0526020611300526020611320526112a051611340527f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffff611360527f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000016113805282600160206112c060c06112e060055afa141692506112c0516000610f8051905082826112805109610f80528282820991506111a0519050828261126051096111a052828282099150611160519050828261124051096111605282828209915061112051905082826112205109611120528282820991506110e0519050828261120051096110e0528282820991506110a051905082826111e051096110a05282828209915061106051905082826111c05109611060528282820991506110205190508282610fe051096110205282828209915081610fe052505080610fe051610fc051096113a052806110205161100051096113c052806110605161104051096113e052806110a051611080510961140052806110e0516110c051096114205280611120516111005109611440528061116051611140510961146052806111a051611180510961148052806105e05161060051096114a052806114a0516105c051086114c052806106205182036114c051086114e05280610820516114e0510961150052806115005161046051096115205280610660516106805109611540528061154051610640510861156052806106a0518203611560510861158052806108405161158051096115a052806115a05161152051086115c052806115c05161046051096115e052806106e05161070051096116005280611600516106c051086116205280610720518203611620510861164052806108605161164051096116605280611660516115e0510861168052806116805161046051096116a052806107605161078051096116c052806116c05161074051086116e052806107a05182036116e0510861170052806108805161170051096117205280611720516116a051086117405280611740516104605109611760528061098051820360010861178052806114805161178051096117a052806117a05161176051086117c052806117c05161046051096117e05280610a4051610a4051096118005280610a40518203611800510861182052806113a05161182051096118405280611840516117e05108611860528061186051610460510961188052806109c05182036109e051086118a05280611480516118a051096118c052806118c05161188051086118e052806118e05161046051096119005280610a20518203610a40510861192052806114805161192051096119405280611940516119005108611960528061196051610460510961198052806113a05182036001086119a052806113e0516113c051086119c05280611400516119c051086119e05280611420516119e05108611a00528061144051611a005108611a20528061146051611a205108611a405280611a405182036119a05108611a605280610260516108c05109611a805280611a80516107e05108611aa052806102c051611aa05108611ac05280610260516108e05109611ae05280611ae0516105c05108611b0052806102c051611b005108611b205280611ac051611b205109611b4052806109a051611b405109611b60528061026051600109611b805280611b80516105805109611ba05280611ba0516107e05108611bc052806102c051611bc05108611be05280610260517f09226b6e22c6f0ca64ec26aad4c86e715b5f898e5e963f25870e56bbe533e9a209611c005280611c00516105805109611c205280611c20516105c05108611c4052806102c051611c405108611c605280611be051611c605109611c80528061098051611c805109611ca05280611ca0518203611b605108611cc05280611a6051611cc05109611ce05280611ce0516119805108611d005280611d00516104605109611d205280610260516109005109611d405280611d40516106405108611d6052806102c051611d605108611d805280610260516109205109611da05280611da0516106c05108611dc052806102c051611dc05108611de05280611d8051611de05109611e005280610a0051611e005109611e205280610260517f13b360d4e82fe915fed16081038f98c211427b87a281bd733c277dbadf10372b09611e405280611e40516105805109611e605280611e60516106405108611e8052806102c051611e805108611ea05280610260517f18afdf23e9bd9302673fc1e076a492d4d65bd18ebc4d854ed189139bab313e5209611ec05280611ec0516105805109611ee05280611ee0516106c05108611f0052806102c051611f005108611f205280611ea051611f205109611f4052806109e051611f405109611f605280611f60518203611e205108611f805280611a6051611f805109611fa05280611fa051611d205108611fc05280611fc0516104605109611fe05280610260516109405109612000528061200051610740510861202052806102c051612020510861204052806102605161096051096120605280612060516107c0510861208052806102c05161208051086120a05280612040516120a051096120c05280610a60516120c051096120e05280610260517ea136ba13afa6c83eb7b82fb370e228e74155e48fb8f1c1cfc33fb0da8afb42096121005280612100516105805109612120528061212051610740510861214052806102c05161214051086121605280610260517f2eb9750dce545f17d492058dd201a1251ff3d9077864583d44eaf9be9008699d0961218052806121805161058051096121a052806121a0516107c051086121c052806102c0516121c051086121e05280612160516121e051096122005280610a4051612200510961222052806122205182036120e051086122405280611a60516122405109612260528061226051611fe0510861228052806122805161046051096122a05280610a805182036001086122c05280611480516122c051096122e052806122e0516122a0510861230052806123005161046051096123205280610a8051610a8051096123405280610a80518203612340510861236052806113a051612360510961238052806123805161232051086123a052806123a05161046051096123c0528061026051610ac051086123e05280610aa0516123e0510961240052806102c051610b00510861242052806124005161242051096124405280610260516107c051086124605280610a8051612460510961248052806102c05161080051086124a05280612480516124a051096124c052806124c051820361244051086124e05280611a60516124e051096125005280612500516123c0510861252052806125205161046051096125405280610b00518203610ac05108612560528061148051612560510961258052806125805161254051086125a052806125a05161046051096125c05280611a605161256051096125e05280610ae0518203610ac0510861260052806125e05161260051096126205280612620516125c051086126405280610f6051610f6051096126605280610f605161266051096126805280610f60516001096126a05280612660516001096126c05280610f805161264051096126e05280610d2051610d2051096127005280610d205161270051096127205280610d205161272051096127405280610d205161274051096127605280610d205161276051096127805280610b4051610b4051096127a05280610b40516127a051096127c05280610b40516127c051096127e05280610b40516127e051096128005280610b405161280051096128205280610b405161282051096128405280610b405161284051096128605280610b405161286051096128805280610b405161288051096128a05280610b40516128a051096128c05280610b40516128c051096128e05280610b40516128e051096129005280610b405161290051096129205280610b405161292051096129405280610b405161294051096129605280610b405161296051096129805280610b405161298051096129a05280610b40516129a051096129c05280610b40516129c051096129e05280610b40516129e05109612a005280610b4051612a005109612a205280610b4051612a205109612a405280610b4051612a405109612a605280610b4051612a605109612a80528060016105c051830309612aa05280610b405161064051830309612ac05280610b4051600109612ae05280612ac051612aa05108612b0052806127a0516106c051830309612b2052806127a051600109612b405280612b2051612b005108612b6052806127c05161074051830309612b8052806127c051600109612ba05280612b8051612b605108612bc052806127e0516107c051830309612be052806127e051600109612c005280612be051612bc05108612c2052806128005161098051830309612c40528061280051600109612c605280612c4051612c205108612c805280612820516109e051830309612ca0528061282051600109612cc05280612ca051612c805108612ce0528061284051610a4051830309612d00528061284051600109612d205280612d0051612ce05108612d40528061286051610a8051830309612d60528061286051600109612d805280612d6051612d405108612da0528061288051610ac051830309612dc0528061288051600109612de05280612dc051612da05108612e0052806128a051610b0051830309612e2052806128a051600109612e405280612e2051612e005108612e6052806128c0516107e051830309612e8052806128c051600109612ea05280612e8051612e605108612ec052806128e05161080051830309612ee052806128e051600109612f005280612ee051612ec05108612f2052806129005161082051830309612f40528061290051600109612f605280612f4051612f205108612f8052806129205161084051830309612fa0528061292051600109612fc05280612fa051612f805108612fe052806129405161086051830309613000528061294051600109613020528061300051612fe051086130405280612960516108805183030961306052806129605160010961308052806130605161304051086130a05280612980516108c0518303096130c05280612980516001096130e052806130c0516130a0510861310052806129a0516108e05183030961312052806129a051600109613140528061312051613100510861316052806129c0516109005183030961318052806129c0516001096131a052806131805161316051086131c052806129e051610920518303096131e052806129e05160010961320052806131e0516131c051086132205280612a0051610940518303096132405280612a005160010961326052806132405161322051086132805280612a2051610960518303096132a05280612a20516001096132c052806132a05161328051086132e05280612a40516126e0518303096133005280612a40516001096133205280612a40516126a051096133405280612a40516126c051096133605280613300516132e051086133805280612a60516108a0518303096133a05280612a60516001096133c052806133a05161338051086133e0528060016133e0510961340052806001612ae0510961342052806001612b40510961344052806001612ba0510961346052806001612c00510961348052806001612c6051096134a052806001612cc051096134c052806001612d2051096134e052806001612d80510961350052806001612de0510961352052806001612e40510961354052806001612ea0510961356052806001612f00510961358052806001612f6051096135a052806001612fc051096135c05280600161302051096135e0528060016130805109613600528060016130e05109613620528060016131405109613640528060016131a051096136605280600161320051096136805280600161326051096136a0528060016132c051096136c05280600161332051096136e0528060016133405109613700528060016133605109613720528060016133c05109613740528060016105e0518303096137605280610b40516106605183030961378052806137805161376051086137a052806127a0516106e0518303096137c052806137c0516137a051086137e052806127c051610760518303096138005280613800516137e0510861382052806127e0516109a0518303096138405280613840516138205108613860528061280051610a005183030961388052806138805161386051086138a0528061282051610a60518303096138c052806138c0516138a051086138e0528061284051610aa0518303096139005280613900516138e051086139205280610d205161392051096139405280610d20516001096139605280610d2051612ae051096139805280610d2051612b4051096139a05280610d2051612ba051096139c05280610d2051612c0051096139e05280610d2051612c605109613a005280610d2051612cc05109613a205280610d2051612d205109613a405280613940516134005108613a60528061396051600108613a805280613980516134205108613aa052806139a0516134405108613ac052806139c0516134605108613ae052806139e0516134a05108613b005280613a00516134c05108613b205280613a20516134e05108613b405280613a40516135005108613b605280600161060051830309613b805280610b405161068051830309613ba05280613ba051613b805108613bc052806127a05161070051830309613be05280613be051613bc05108613c0052806127c05161078051830309613c205280613c2051613c005108613c40528061270051613c405109613c60528061270051600109613c80528061270051612ae05109613ca0528061270051612b405109613cc0528061270051612ba05109613ce05280613c6051613a605108613d005280613c8051613a805108613d205280613ca051613aa05108613d405280613cc051613ac05108613d605280613ce051613ae05108613d805280600161062051830309613da05280610b40516106a051830309613dc05280613dc051613da05108613de052806127a05161072051830309613e005280613e0051613de05108613e2052806127c0516107a051830309613e405280613e4051613e205108613e60528061272051613e605109613e80528061272051600109613ea0528061272051612ae05109613ec0528061272051612b405109613ee0528061272051612ba05109613f005280613e8051613d005108613f205280613ea051613d205108613f405280613ec051613d405108613f605280613ee051613d605108613f805280613f0051613d805108613fa052806001610a2051830309613fc05280610b40516109c051830309613fe05280613fe051613fc051086140005280612740516140005109614020528061274051600109614040528061274051612ae05109614060528061402051613f205108614080528061404051613b2051086140a0528061406051613b0051086140c052806001610ae0518303096140e05280612760516140e05109614100528061276051600109614120528061410051614080510861414052806141205161352051086141605280610580516001096141805280614180516001096141a05280610580517f304cd1e79cfa5b0f054e981a27ed7706e7ea6b06a7f266ef8db819c179c2c3ea096141c052806141c05161396051096141e05280610580517f09d2cc4b5782fbe923e49ace3f647643a5f5d8fb89091c3ababd582133584b2909614200528061420051613c8051096142205280610580517f1b9dc92942bfad9dc4bab51b820a33bc4da69d92ec5bbb256e55edec25e3b05b09614240528061424051613ea051096142605280610580517f2ed3ad80154160493a49fb866bafcde224c1058bdf972b5520fa5689f14f52650961428052806142805161404051096142a05280610580517f193586da872cdeff023d6ab2263a131b4780db8878be3c3b7f8f019c06fcb0fb096142c052806142c05161412051096142e05260016143005260026143205261414051614340528260016040614300606061430060075afa141692506020516143605260405161438052613f40516143a0528260016040614360606061436060075afa14169250614300516143c052614320516143e0526143605161440052614380516144205282600160406143c060806143c060065afa141692506060516144405260805161446052613f6051614480528260016040614440606061444060075afa141692506143c0516144a0526143e0516144c052614440516144e052614460516145005282600160406144a060806144a060065afa1416925060a0516145205260c05161454052613f8051614560528260016040614520606061452060075afa141692506144a051614580526144c0516145a052614520516145c052614540516145e0528260016040614580608061458060065afa1416925060e051614600526101005161462052613fa051614640528260016040614600606061460060075afa1416925061458051614660526145a05161468052614600516146a052614620516146c0528260016040614660608061466060065afa14169250610120516146e0526101405161470052613480516147205282600160406146e060606146e060075afa14169250614660516147405261468051614760526146e05161478052614700516147a0528260016040614740608061474060065afa14169250610300516147c052610320516147e0526140c0516148005282600160406147c060606147c060075afa14169250614740516148205261476051614840526147c051614860526147e051614880528260016040614820608061482060065afa14169250610340516148a052610360516148c0526140a0516148e05282600160406148a060606148a060075afa14169250614820516149005261484051614920526148a051614940526148c051614960528260016040614900608061490060065afa1416925061038051614980526103a0516149a052613b40516149c0528260016040614980606061498060075afa14169250614900516149e05261492051614a005261498051614a20526149a051614a405282600160406149e060806149e060065afa141692506103c051614a60526103e051614a8052613b6051614aa0528260016040614a606060614a6060075afa141692506149e051614ac052614a0051614ae052614a6051614b0052614a8051614b20528260016040614ac06080614ac060065afa141692506101c051614b40526101e051614b605261416051614b80528260016040614b406060614b4060075afa14169250614ac051614ba052614ae051614bc052614b4051614be052614b6051614c00528260016040614ba06080614ba060065afa1416925061020051614c205261022051614c405261354051614c60528260016040614c206060614c2060075afa14169250614ba051614c8052614bc051614ca052614c2051614cc052614c4051614ce0528260016040614c806080614c8060065afa141692507f0dff8d04331a85b6120dc7c6931fc454e9037c9b93e38a4f71aa5fd9fe75bc97614d00527f14bd60e4170e4bbe0b1e1e4d15b2d437df5866b83fcafe0753749e17d75c2cd9614d205261356051614d40528260016040614d006060614d0060075afa14169250614c8051614d6052614ca051614d8052614d0051614da052614d2051614dc0528260016040614d606080614d6060065afa141692507f2f579160607cc547a54ef72e5a1a2966a65305c955cf8d94f507169386a10f4c614de0527f15932d491aaaa6d3673eeb19941a96ee53b011a6923028a70466a155b753d46b614e005261358051614e20528260016040614de06060614de060075afa14169250614d6051614e4052614d8051614e6052614de051614e8052614e0051614ea0528260016040614e406080614e4060065afa141692507f11296fee9462167f3654dc994f115d276f9341f4a09938e8709c254b45a8184e614ec0527e73a5ff1d83202c85f53e39701a5b81e120e34d4144c3685628f11fe600d1c8614ee0526135a051614f00528260016040614ec06060614ec060075afa14169250614e4051614f2052614e6051614f4052614ec051614f6052614ee051614f80528260016040614f206080614f2060065afa141692507f24a62d386c435b4fde43b1101de79c96bdcab6e4c3c27d64a84dd7cdf40a19cd614fa0527f28baaa1cd3c8564f7592474e70b2be39f920e563f2653f1a468e44750fee28fc614fc0526135c051614fe0528260016040614fa06060614fa060075afa14169250614f205161500052614f405161502052614fa05161504052614fc051615060528260016040615000608061500060065afa141692507f2f5dc887b3e303b298a275a19cc20346f4ea520da08559fba986ed9705c94ca5615080527f21be9078a0b99102948250140813cc1731845eeb648e8b8638b33e995d426a256150a0526135e0516150c0528260016040615080606061508060075afa14169250615000516150e052615020516151005261508051615120526150a0516151405282600160406150e060806150e060065afa141692507f2a0677efd45c4ab5d3b792b8fd045a67cf59648d08b62595b7f88dd5d05aee33615160527f03ee72dc1dae3d5b618521ea55fe56626e5cda6d307ca649d571a94b3ef7bc8761518052613600516151a0528260016040615160606061516060075afa141692506150e0516151c052615100516151e0526151605161520052615180516152205282600160406151c060806151c060065afa141692507f0c11bdfa7a12ca0606d461516b1812be1116d7ff14f7dd6de65aaa982a607acf615240527f06acc27ceaaa3e95505f13892883f8521adedc9bbd43598e868a17f02ae336256152605261362051615280528260016040615240606061524060075afa141692506151c0516152a0526151e0516152c052615240516152e052615260516153005282600160406152a060806152a060065afa141692507f22304e7bee3c7aff8297144af6ea0c074de44a927d8752e0d9c7b45b1f05fccd615320527f2f1313f85baf7c33b5f9ed033721c82944d69e41390dd33da9513bd99676ca666153405261364051615360528260016040615320606061532060075afa141692506152a051615380526152c0516153a052615320516153c052615340516153e0528260016040615380608061538060065afa141692507f1c708d04f001424ee7b2077673e84220c0fb42b5fffb2db82d818fa9d9b80c1e615400527f0d4766ae417fe4d18b46fda1b18c8665b816f9b980fe37817a64937a4fce00e26154205261366051615440528260016040615400606061540060075afa1416925061538051615460526153a05161548052615400516154a052615420516154c0528260016040615460608061546060065afa141692507f14b76f83cf9e09d83b0fed71c64b7e4e7ed34e57b1ad256c037910dcc4e53bcc6154e0527e842333c00cdcf8cd03a588e7395720b824e2c8d7f83d34b3eaed2e5ed660cb61550052613680516155205282600160406154e060606154e060075afa14169250615460516155405261548051615560526154e05161558052615500516155a0528260016040615540608061554060065afa141692507f1bd997cdf68f8cb6f57e1e6e1f1360170161786c9f9e7c68f107276b42c765766155c0527f2d2df447a3729e8922d95dd626a7b3e43b2eeb91c9f8710af3915fc2ab4d52a56155e0526136a0516156005282600160406155c060606155c060075afa14169250615540516156205261556051615640526155c051615660526155e051615680528260016040615620608061562060065afa141692507f2133d421c4f201a8c7d877c74d0036606e3d3fe700f25adca7f2fb9daeb2d5786156a0527f14ce0243e1d996a67c02c08537383b983b4f193a780cfdc5676f15a1fe8a0bbc6156c0526136c0516156e05282600160406156a060606156a060075afa14169250615620516157005261564051615720526156a051615740526156c051615760528260016040615700608061570060065afa141692506104a051615780526104c0516157a0526136e0516157c0528260016040615780606061578060075afa14169250615700516157e052615720516158005261578051615820526157a0516158405282600160406157e060806157e060065afa141692506104e051615860526105005161588052613700516158a0528260016040615860606061586060075afa141692506157e0516158c052615800516158e0526158605161590052615880516159205282600160406158c060806158c060065afa141692506105205161594052610540516159605261372051615980528260016040615940606061594060075afa141692506158c0516159a0526158e0516159c052615940516159e05261596051615a005282600160406159a060806159a060065afa1416925061040051615a205261042051615a405261374051615a60528260016040615a206060615a2060075afa141692506159a051615a80526159c051615aa052615a2051615ac052615a4051615ae0528260016040615a806080615a8060065afa14169250610b8051615b0052610ba051615b20526141a051615b40528260016040615b006060615b0060075afa14169250615a8051615b6052615aa051615b8052615b0051615ba052615b2051615bc0528260016040615b606080615b6060065afa14169250610bc051615be052610be051615c00526141e051615c20528260016040615be06060615be060075afa14169250615b6051615c4052615b8051615c6052615be051615c8052615c0051615ca0528260016040615c406080615c4060065afa14169250610c0051615cc052610c2051615ce05261422051615d00528260016040615cc06060615cc060075afa14169250615c4051615d2052615c6051615d4052615cc051615d6052615ce051615d80528260016040615d206080615d2060065afa14169250610c4051615da052610c6051615dc05261426051615de0528260016040615da06060615da060075afa14169250615d2051615e0052615d4051615e2052615da051615e4052615dc051615e60528260016040615e006080615e0060065afa14169250610c8051615e8052610ca051615ea0526142a051615ec0528260016040615e806060615e8060075afa14169250615e0051615ee052615e2051615f0052615e8051615f2052615ea051615f40528260016040615ee06080615ee060065afa14169250610cc051615f6052610ce051615f80526142e051615fa0528260016040615f606060615f6060075afa14169250615ee051615fc052615f0051615fe052615f605161600052615f8051616020528260016040615fc06080615fc060065afa14169250610bc05161604052610be0516160605261396051616080528260016040616040606061604060075afa14169250610b80516160a052610ba0516160c052616040516160e052616060516161005282600160406160a060806160a060065afa14169250610c005161612052610c205161614052613c8051616160528260016040616120606061612060075afa141692506160a051616180526160c0516161a052616120516161c052616140516161e0528260016040616180608061618060065afa14169250610c405161620052610c605161622052613ea051616240528260016040616200606061620060075afa1416925061618051616260526161a05161628052616200516162a052616220516162c0528260016040616260608061626060065afa14169250610c80516162e052610ca05161630052614040516163205282600160406162e060606162e060075afa14169250616260516163405261628051616360526162e05161638052616300516163a0528260016040616340608061634060065afa14169250610cc0516163c052610ce0516163e052614120516164005282600160406163c060606163c060075afa14169250616340516164205261636051616440526163c051616460526163e051616480528260016040616420608061642060065afa14169250615fc0516164a052615fe0516164c0527f198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c26164e0527f1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed616500527f090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b616520527f12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa61654052616420516165605261644051616580527f0181624e80f3d6ae28df7e01eaeab1c0e919877a3b8a6b7fbc69a6817d596ea26165a0527f1783d30dcb12d259bb89098addf6280fa4b653be7a152542a28f7b926e27e6486165c0527eae44489d41a0d179e2dfdc03bddd883b7109f8b6ae316a59e815c1a6b353046165e0527f0b2147ab62a386bd63e6de1522109b8c9588ab466f5aadfde8c41ca3749423ee6166005282600160206164a06101806164a060085afa141692508260016164a05114169250826134b557600080fd5b600080f3";
}
