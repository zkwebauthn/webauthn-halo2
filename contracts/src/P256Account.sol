// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import "openzeppelin-contracts/contracts/proxy/utils/UUPSUpgradeable.sol";

import "./SimpleAccount.sol";
import "./core/BaseAccount.sol";
import "./callback/TokenCallbackHandler.sol";

/**
 * Account that validates P-256 signature for UserOperations.
 */
contract P256Account is Initializable, SimpleAccount {
    using ECDSA for bytes32;

    address public verifier;
    IEntryPoint public _entryPoint;
    bytes public publicKey;
    uint256 InactiveTimeLimit;
    address inheritor;
    uint256 lastActiveTime;

    constructor(IEntryPoint _newEntryPoint) SimpleAccount(_newEntryPoint) {}

    function initialize(
        IEntryPoint _newEntryPoint,
        bytes memory _publicKey
    ) public initializer {
        _entryPoint = _newEntryPoint;
        publicKey = _publicKey;
        InactiveTimeLimit = 0;
        inheritor = address(0);
        lastActiveTime = block.timestamp;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function _verifyP256Proof(
        uint256[] memory pubInputs,
        bytes memory proof
    ) public view returns (bool) {
        bool success = true;
        bytes32[816] memory transcript;
        assembly {
            let
                f_p
            := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
            let
                f_q
            := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            function validate_ec_point(x, y) -> valid {
                {
                    let x_lt_p := lt(
                        x,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let y_lt_p := lt(
                        y,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    valid := and(x_lt_p, y_lt_p)
                }
                {
                    let y_square := mulmod(
                        y,
                        y,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let x_square := mulmod(
                        x,
                        x,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let x_cube := mulmod(
                        x_square,
                        x,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let x_cube_plus_3 := addmod(
                        x_cube,
                        3,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let is_affine := eq(x_cube_plus_3, y_square)
                    valid := and(valid, is_affine)
                }
            }
            mstore(
                add(transcript, 0x0),
                9863973964072777430012735887744687009916260689416585824100641760772619815460
            )
            {
                let x := mload(add(pubInputs, 0x20))
                mstore(add(transcript, 0x20), x)
                let y := mload(add(proof, 0x20))
                mstore(add(transcript, 0x40), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x40))
                mstore(add(transcript, 0x60), x)
                let y := mload(add(proof, 0x60))
                mstore(add(transcript, 0x80), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x80))
                mstore(add(transcript, 0xa0), x)
                let y := mload(add(proof, 0xa0))
                mstore(add(transcript, 0xc0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0xc0))
                mstore(add(transcript, 0xe0), x)
                let y := mload(add(proof, 0xe0))
                mstore(add(transcript, 0x100), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x100))
                mstore(add(transcript, 0x120), x)
                let y := mload(add(proof, 0x120))
                mstore(add(transcript, 0x140), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(add(transcript, 0x160), keccak256(add(transcript, 0x0), 352))
            {
                let hash := mload(add(transcript, 0x160))
                mstore(add(transcript, 0x180), mod(hash, f_q))
                mstore(add(transcript, 0x1a0), hash)
            }
            {
                let x := mload(add(proof, 0x140))
                mstore(add(transcript, 0x1c0), x)
                let y := mload(add(proof, 0x160))
                mstore(add(transcript, 0x1e0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x180))
                mstore(add(transcript, 0x200), x)
                let y := mload(add(proof, 0x1a0))
                mstore(add(transcript, 0x220), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x240),
                keccak256(add(transcript, 0x1a0), 160)
            )
            {
                let hash := mload(add(transcript, 0x240))
                mstore(add(transcript, 0x260), mod(hash, f_q))
                mstore(add(transcript, 0x280), hash)
            }
            mstore8(add(transcript, 0x2a0), 1)
            mstore(
                add(transcript, 0x2a0),
                keccak256(add(transcript, 0x280), 33)
            )
            {
                let hash := mload(add(transcript, 0x2a0))
                mstore(add(transcript, 0x2c0), mod(hash, f_q))
                mstore(add(transcript, 0x2e0), hash)
            }
            {
                let x := mload(add(proof, 0x1c0))
                mstore(add(transcript, 0x300), x)
                let y := mload(add(proof, 0x1e0))
                mstore(add(transcript, 0x320), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x200))
                mstore(add(transcript, 0x340), x)
                let y := mload(add(proof, 0x220))
                mstore(add(transcript, 0x360), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x240))
                mstore(add(transcript, 0x380), x)
                let y := mload(add(proof, 0x260))
                mstore(add(transcript, 0x3a0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x280))
                mstore(add(transcript, 0x3c0), x)
                let y := mload(add(proof, 0x2a0))
                mstore(add(transcript, 0x3e0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x2c0))
                mstore(add(transcript, 0x400), x)
                let y := mload(add(proof, 0x2e0))
                mstore(add(transcript, 0x420), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x440),
                keccak256(add(transcript, 0x2e0), 352)
            )
            {
                let hash := mload(add(transcript, 0x440))
                mstore(add(transcript, 0x460), mod(hash, f_q))
                mstore(add(transcript, 0x480), hash)
            }
            {
                let x := mload(add(proof, 0x300))
                mstore(add(transcript, 0x4a0), x)
                let y := mload(add(proof, 0x320))
                mstore(add(transcript, 0x4c0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x340))
                mstore(add(transcript, 0x4e0), x)
                let y := mload(add(proof, 0x360))
                mstore(add(transcript, 0x500), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x380))
                mstore(add(transcript, 0x520), x)
                let y := mload(add(proof, 0x3a0))
                mstore(add(transcript, 0x540), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x560),
                keccak256(add(transcript, 0x480), 224)
            )
            {
                let hash := mload(add(transcript, 0x560))
                mstore(add(transcript, 0x580), mod(hash, f_q))
                mstore(add(transcript, 0x5a0), hash)
            }
            mstore(add(transcript, 0x5c0), mod(mload(add(proof, 0x3c0)), f_q))
            mstore(add(transcript, 0x5e0), mod(mload(add(proof, 0x3e0)), f_q))
            mstore(add(transcript, 0x600), mod(mload(add(proof, 0x400)), f_q))
            mstore(add(transcript, 0x620), mod(mload(add(proof, 0x420)), f_q))
            mstore(add(transcript, 0x640), mod(mload(add(proof, 0x440)), f_q))
            mstore(add(transcript, 0x660), mod(mload(add(proof, 0x460)), f_q))
            mstore(add(transcript, 0x680), mod(mload(add(proof, 0x480)), f_q))
            mstore(add(transcript, 0x6a0), mod(mload(add(proof, 0x4a0)), f_q))
            mstore(add(transcript, 0x6c0), mod(mload(add(proof, 0x4c0)), f_q))
            mstore(add(transcript, 0x6e0), mod(mload(add(proof, 0x4e0)), f_q))
            mstore(add(transcript, 0x700), mod(mload(add(proof, 0x500)), f_q))
            mstore(add(transcript, 0x720), mod(mload(add(proof, 0x520)), f_q))
            mstore(add(transcript, 0x740), mod(mload(add(proof, 0x540)), f_q))
            mstore(add(transcript, 0x760), mod(mload(add(proof, 0x560)), f_q))
            mstore(add(transcript, 0x780), mod(mload(add(proof, 0x580)), f_q))
            mstore(add(transcript, 0x7a0), mod(mload(add(proof, 0x5a0)), f_q))
            mstore(add(transcript, 0x7c0), mod(mload(add(proof, 0x5c0)), f_q))
            mstore(add(transcript, 0x7e0), mod(mload(add(proof, 0x5e0)), f_q))
            mstore(add(transcript, 0x800), mod(mload(add(proof, 0x600)), f_q))
            mstore(add(transcript, 0x820), mod(mload(add(proof, 0x620)), f_q))
            mstore(add(transcript, 0x840), mod(mload(add(proof, 0x640)), f_q))
            mstore(add(transcript, 0x860), mod(mload(add(proof, 0x660)), f_q))
            mstore(add(transcript, 0x880), mod(mload(add(proof, 0x680)), f_q))
            mstore(add(transcript, 0x8a0), mod(mload(add(proof, 0x6a0)), f_q))
            mstore(add(transcript, 0x8c0), mod(mload(add(proof, 0x6c0)), f_q))
            mstore(add(transcript, 0x8e0), mod(mload(add(proof, 0x6e0)), f_q))
            mstore(add(transcript, 0x900), mod(mload(add(proof, 0x700)), f_q))
            mstore(add(transcript, 0x920), mod(mload(add(proof, 0x720)), f_q))
            mstore(add(transcript, 0x940), mod(mload(add(proof, 0x740)), f_q))
            mstore(add(transcript, 0x960), mod(mload(add(proof, 0x760)), f_q))
            mstore(add(transcript, 0x980), mod(mload(add(proof, 0x780)), f_q))
            mstore(add(transcript, 0x9a0), mod(mload(add(proof, 0x7a0)), f_q))
            mstore(add(transcript, 0x9c0), mod(mload(add(proof, 0x7c0)), f_q))
            mstore(add(transcript, 0x9e0), mod(mload(add(proof, 0x7e0)), f_q))
            mstore(add(transcript, 0xa00), mod(mload(add(proof, 0x800)), f_q))
            mstore(add(transcript, 0xa20), mod(mload(add(proof, 0x820)), f_q))
            mstore(add(transcript, 0xa40), mod(mload(add(proof, 0x840)), f_q))
            mstore(add(transcript, 0xa60), mod(mload(add(proof, 0x860)), f_q))
            mstore(add(transcript, 0xa80), mod(mload(add(proof, 0x880)), f_q))
            mstore(add(transcript, 0xaa0), mod(mload(add(proof, 0x8a0)), f_q))
            mstore(add(transcript, 0xac0), mod(mload(add(proof, 0x8c0)), f_q))
            mstore(add(transcript, 0xae0), mod(mload(add(proof, 0x8e0)), f_q))
            mstore(add(transcript, 0xb00), mod(mload(add(proof, 0x900)), f_q))
            mstore(
                add(transcript, 0xb20),
                keccak256(add(transcript, 0x5a0), 1408)
            )
            {
                let hash := mload(add(transcript, 0xb20))
                mstore(add(transcript, 0xb40), mod(hash, f_q))
                mstore(add(transcript, 0xb60), hash)
            }
            {
                let x := mload(add(proof, 0x920))
                mstore(add(transcript, 0xb80), x)
                let y := mload(add(proof, 0x940))
                mstore(add(transcript, 0xba0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x960))
                mstore(add(transcript, 0xbc0), x)
                let y := mload(add(proof, 0x980))
                mstore(add(transcript, 0xbe0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x9a0))
                mstore(add(transcript, 0xc00), x)
                let y := mload(add(proof, 0x9c0))
                mstore(add(transcript, 0xc20), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x9e0))
                mstore(add(transcript, 0xc40), x)
                let y := mload(add(proof, 0xa00))
                mstore(add(transcript, 0xc60), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0xa20))
                mstore(add(transcript, 0xc80), x)
                let y := mload(add(proof, 0xa40))
                mstore(add(transcript, 0xca0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0xa60))
                mstore(add(transcript, 0xcc0), x)
                let y := mload(add(proof, 0xa80))
                mstore(add(transcript, 0xce0), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0xd00),
                keccak256(add(transcript, 0xb60), 416)
            )
            {
                let hash := mload(add(transcript, 0xd00))
                mstore(add(transcript, 0xd20), mod(hash, f_q))
                mstore(add(transcript, 0xd40), hash)
            }
            mstore(
                add(transcript, 0xd60),
                mulmod(
                    mload(add(transcript, 0x580)),
                    mload(add(transcript, 0x580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xd80),
                mulmod(
                    mload(add(transcript, 0xd60)),
                    mload(add(transcript, 0xd60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xda0),
                mulmod(
                    mload(add(transcript, 0xd80)),
                    mload(add(transcript, 0xd80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xdc0),
                mulmod(
                    mload(add(transcript, 0xda0)),
                    mload(add(transcript, 0xda0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xde0),
                mulmod(
                    mload(add(transcript, 0xdc0)),
                    mload(add(transcript, 0xdc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe00),
                mulmod(
                    mload(add(transcript, 0xde0)),
                    mload(add(transcript, 0xde0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe20),
                mulmod(
                    mload(add(transcript, 0xe00)),
                    mload(add(transcript, 0xe00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe40),
                mulmod(
                    mload(add(transcript, 0xe20)),
                    mload(add(transcript, 0xe20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe60),
                mulmod(
                    mload(add(transcript, 0xe40)),
                    mload(add(transcript, 0xe40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe80),
                mulmod(
                    mload(add(transcript, 0xe60)),
                    mload(add(transcript, 0xe60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xea0),
                mulmod(
                    mload(add(transcript, 0xe80)),
                    mload(add(transcript, 0xe80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xec0),
                mulmod(
                    mload(add(transcript, 0xea0)),
                    mload(add(transcript, 0xea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xee0),
                mulmod(
                    mload(add(transcript, 0xec0)),
                    mload(add(transcript, 0xec0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf00),
                mulmod(
                    mload(add(transcript, 0xee0)),
                    mload(add(transcript, 0xee0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf20),
                mulmod(
                    mload(add(transcript, 0xf00)),
                    mload(add(transcript, 0xf00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf40),
                mulmod(
                    mload(add(transcript, 0xf20)),
                    mload(add(transcript, 0xf20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf60),
                mulmod(
                    mload(add(transcript, 0xf40)),
                    mload(add(transcript, 0xf40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf80),
                addmod(
                    mload(add(transcript, 0xf60)),
                    21888242871839275222246405745257275088548364400416034343698204186575808495616,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xfa0),
                mulmod(
                    mload(add(transcript, 0xf80)),
                    21888075877798810139885396174900942254113179552665176677420557563313886988289,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xfc0),
                mulmod(
                    mload(add(transcript, 0xfa0)),
                    21180393220728113421338195116216869725258066600961496947533653125588029756005,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xfe0),
                addmod(
                    mload(add(transcript, 0x580)),
                    707849651111161800908210629040405363290297799454537396164551060987778739612,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1000),
                mulmod(
                    mload(add(transcript, 0xfa0)),
                    18801136258871406524726641978934912926273987048785013233465874845411408769764,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1020),
                addmod(
                    mload(add(transcript, 0x580)),
                    3087106612967868697519763766322362162274377351631021110232329341164399725853,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1040),
                mulmod(
                    mload(add(transcript, 0xfa0)),
                    13137266746974929847674828718073699700748973485900204084410541910719500618841,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1060),
                addmod(
                    mload(add(transcript, 0x580)),
                    8750976124864345374571577027183575387799390914515830259287662275856307876776,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1080),
                mulmod(
                    mload(add(transcript, 0xfa0)),
                    14204982954615820785730815556166377574172276341958019443243371773666809943588,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x10a0),
                addmod(
                    mload(add(transcript, 0x580)),
                    7683259917223454436515590189090897514376088058458014900454832412908998552029,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x10c0),
                mulmod(
                    mload(add(transcript, 0xfa0)),
                    9798514389911400568976296423560720718971335345616984532185711118739339214189,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x10e0),
                addmod(
                    mload(add(transcript, 0x580)),
                    12089728481927874653270109321696554369577029054799049811512493067836469281428,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1100),
                mulmod(
                    mload(add(transcript, 0xfa0)),
                    5857228514216831962358810454360739186987616060007133076514874820078026801648,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1120),
                addmod(
                    mload(add(transcript, 0x580)),
                    16031014357622443259887595290896535901560748340408901267183329366497781693969,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1140),
                mulmod(
                    mload(add(transcript, 0xfa0)),
                    11402394834529375719535454173347509224290498423785625657829583372803806900475,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1160),
                addmod(
                    mload(add(transcript, 0x580)),
                    10485848037309899502710951571909765864257865976630408685868620813772001595142,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1180),
                mulmod(mload(add(transcript, 0xfa0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x11a0),
                addmod(
                    mload(add(transcript, 0x580)),
                    21888242871839275222246405745257275088548364400416034343698204186575808495616,
                    f_q
                )
            )
            {
                let prod := mload(add(transcript, 0xfe0))
                prod := mulmod(mload(add(transcript, 0x1020)), prod, f_q)
                mstore(add(transcript, 0x11c0), prod)
                prod := mulmod(mload(add(transcript, 0x1060)), prod, f_q)
                mstore(add(transcript, 0x11e0), prod)
                prod := mulmod(mload(add(transcript, 0x10a0)), prod, f_q)
                mstore(add(transcript, 0x1200), prod)
                prod := mulmod(mload(add(transcript, 0x10e0)), prod, f_q)
                mstore(add(transcript, 0x1220), prod)
                prod := mulmod(mload(add(transcript, 0x1120)), prod, f_q)
                mstore(add(transcript, 0x1240), prod)
                prod := mulmod(mload(add(transcript, 0x1160)), prod, f_q)
                mstore(add(transcript, 0x1260), prod)
                prod := mulmod(mload(add(transcript, 0x11a0)), prod, f_q)
                mstore(add(transcript, 0x1280), prod)
                prod := mulmod(mload(add(transcript, 0xf80)), prod, f_q)
                mstore(add(transcript, 0x12a0), prod)
            }
            mstore(add(transcript, 0x12e0), 32)
            mstore(add(transcript, 0x1300), 32)
            mstore(add(transcript, 0x1320), 32)
            mstore(add(transcript, 0x1340), mload(add(transcript, 0x12a0)))
            mstore(
                add(transcript, 0x1360),
                21888242871839275222246405745257275088548364400416034343698204186575808495615
            )
            mstore(
                add(transcript, 0x1380),
                21888242871839275222246405745257275088548364400416034343698204186575808495617
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x5,
                        add(transcript, 0x12e0),
                        0xc0,
                        add(transcript, 0x12c0),
                        0x20
                    ),
                    1
                ),
                success
            )
            {
                let inv := mload(add(transcript, 0x12c0))
                let v
                v := mload(add(transcript, 0xf80))
                mstore(
                    add(transcript, 0xf80),
                    mulmod(mload(add(transcript, 0x1280)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x11a0))
                mstore(
                    add(transcript, 0x11a0),
                    mulmod(mload(add(transcript, 0x1260)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1160))
                mstore(
                    add(transcript, 0x1160),
                    mulmod(mload(add(transcript, 0x1240)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1120))
                mstore(
                    add(transcript, 0x1120),
                    mulmod(mload(add(transcript, 0x1220)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x10e0))
                mstore(
                    add(transcript, 0x10e0),
                    mulmod(mload(add(transcript, 0x1200)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x10a0))
                mstore(
                    add(transcript, 0x10a0),
                    mulmod(mload(add(transcript, 0x11e0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1060))
                mstore(
                    add(transcript, 0x1060),
                    mulmod(mload(add(transcript, 0x11c0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1020))
                mstore(
                    add(transcript, 0x1020),
                    mulmod(mload(add(transcript, 0xfe0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                mstore(add(transcript, 0xfe0), inv)
            }
            mstore(
                add(transcript, 0x13a0),
                mulmod(
                    mload(add(transcript, 0xfc0)),
                    mload(add(transcript, 0xfe0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x13c0),
                mulmod(
                    mload(add(transcript, 0x1000)),
                    mload(add(transcript, 0x1020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x13e0),
                mulmod(
                    mload(add(transcript, 0x1040)),
                    mload(add(transcript, 0x1060)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1400),
                mulmod(
                    mload(add(transcript, 0x1080)),
                    mload(add(transcript, 0x10a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1420),
                mulmod(
                    mload(add(transcript, 0x10c0)),
                    mload(add(transcript, 0x10e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1440),
                mulmod(
                    mload(add(transcript, 0x1100)),
                    mload(add(transcript, 0x1120)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1460),
                mulmod(
                    mload(add(transcript, 0x1140)),
                    mload(add(transcript, 0x1160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1480),
                mulmod(
                    mload(add(transcript, 0x1180)),
                    mload(add(transcript, 0x11a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14a0),
                mulmod(
                    mload(add(transcript, 0x600)),
                    mload(add(transcript, 0x5e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14c0),
                addmod(
                    mload(add(transcript, 0x5c0)),
                    mload(add(transcript, 0x14a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14e0),
                addmod(
                    mload(add(transcript, 0x14c0)),
                    sub(f_q, mload(add(transcript, 0x620))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1500),
                mulmod(
                    mload(add(transcript, 0x14e0)),
                    mload(add(transcript, 0x820)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1520),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x1500)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1540),
                mulmod(
                    mload(add(transcript, 0x680)),
                    mload(add(transcript, 0x660)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1560),
                addmod(
                    mload(add(transcript, 0x640)),
                    mload(add(transcript, 0x1540)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1580),
                addmod(
                    mload(add(transcript, 0x1560)),
                    sub(f_q, mload(add(transcript, 0x6a0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15a0),
                mulmod(
                    mload(add(transcript, 0x1580)),
                    mload(add(transcript, 0x840)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15c0),
                addmod(
                    mload(add(transcript, 0x1520)),
                    mload(add(transcript, 0x15a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15e0),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x15c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1600),
                mulmod(
                    mload(add(transcript, 0x700)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1620),
                addmod(
                    mload(add(transcript, 0x6c0)),
                    mload(add(transcript, 0x1600)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1640),
                addmod(
                    mload(add(transcript, 0x1620)),
                    sub(f_q, mload(add(transcript, 0x720))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1660),
                mulmod(
                    mload(add(transcript, 0x1640)),
                    mload(add(transcript, 0x860)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1680),
                addmod(
                    mload(add(transcript, 0x15e0)),
                    mload(add(transcript, 0x1660)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x16a0),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x1680)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x16c0),
                mulmod(
                    mload(add(transcript, 0x780)),
                    mload(add(transcript, 0x760)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x16e0),
                addmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x16c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1700),
                addmod(
                    mload(add(transcript, 0x16e0)),
                    sub(f_q, mload(add(transcript, 0x7a0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1720),
                mulmod(
                    mload(add(transcript, 0x1700)),
                    mload(add(transcript, 0x880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1740),
                addmod(
                    mload(add(transcript, 0x16a0)),
                    mload(add(transcript, 0x1720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1760),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x1740)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1780),
                addmod(1, sub(f_q, mload(add(transcript, 0x980))), f_q)
            )
            mstore(
                add(transcript, 0x17a0),
                mulmod(
                    mload(add(transcript, 0x1780)),
                    mload(add(transcript, 0x1480)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x17c0),
                addmod(
                    mload(add(transcript, 0x1760)),
                    mload(add(transcript, 0x17a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x17e0),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x17c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1800),
                mulmod(
                    mload(add(transcript, 0xa40)),
                    mload(add(transcript, 0xa40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1820),
                addmod(
                    mload(add(transcript, 0x1800)),
                    sub(f_q, mload(add(transcript, 0xa40))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1840),
                mulmod(
                    mload(add(transcript, 0x1820)),
                    mload(add(transcript, 0x13a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1860),
                addmod(
                    mload(add(transcript, 0x17e0)),
                    mload(add(transcript, 0x1840)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1880),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x1860)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x18a0),
                addmod(
                    mload(add(transcript, 0x9e0)),
                    sub(f_q, mload(add(transcript, 0x9c0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x18c0),
                mulmod(
                    mload(add(transcript, 0x18a0)),
                    mload(add(transcript, 0x1480)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x18e0),
                addmod(
                    mload(add(transcript, 0x1880)),
                    mload(add(transcript, 0x18c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1900),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x18e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1920),
                addmod(
                    mload(add(transcript, 0xa40)),
                    sub(f_q, mload(add(transcript, 0xa20))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1940),
                mulmod(
                    mload(add(transcript, 0x1920)),
                    mload(add(transcript, 0x1480)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1960),
                addmod(
                    mload(add(transcript, 0x1900)),
                    mload(add(transcript, 0x1940)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1980),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x1960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x19a0),
                addmod(1, sub(f_q, mload(add(transcript, 0x13a0))), f_q)
            )
            mstore(
                add(transcript, 0x19c0),
                addmod(
                    mload(add(transcript, 0x13c0)),
                    mload(add(transcript, 0x13e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x19e0),
                addmod(
                    mload(add(transcript, 0x19c0)),
                    mload(add(transcript, 0x1400)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a00),
                addmod(
                    mload(add(transcript, 0x19e0)),
                    mload(add(transcript, 0x1420)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a20),
                addmod(
                    mload(add(transcript, 0x1a00)),
                    mload(add(transcript, 0x1440)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a40),
                addmod(
                    mload(add(transcript, 0x1a20)),
                    mload(add(transcript, 0x1460)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a60),
                addmod(
                    mload(add(transcript, 0x19a0)),
                    sub(f_q, mload(add(transcript, 0x1a40))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a80),
                mulmod(
                    mload(add(transcript, 0x8c0)),
                    mload(add(transcript, 0x260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1aa0),
                addmod(
                    mload(add(transcript, 0x7e0)),
                    mload(add(transcript, 0x1a80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ac0),
                addmod(
                    mload(add(transcript, 0x1aa0)),
                    mload(add(transcript, 0x2c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ae0),
                mulmod(
                    mload(add(transcript, 0x8e0)),
                    mload(add(transcript, 0x260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b00),
                addmod(
                    mload(add(transcript, 0x5c0)),
                    mload(add(transcript, 0x1ae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b20),
                addmod(
                    mload(add(transcript, 0x1b00)),
                    mload(add(transcript, 0x2c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b40),
                mulmod(
                    mload(add(transcript, 0x1b20)),
                    mload(add(transcript, 0x1ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b60),
                mulmod(
                    mload(add(transcript, 0x1b40)),
                    mload(add(transcript, 0x9a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b80),
                mulmod(1, mload(add(transcript, 0x260)), f_q)
            )
            mstore(
                add(transcript, 0x1ba0),
                mulmod(
                    mload(add(transcript, 0x580)),
                    mload(add(transcript, 0x1b80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1bc0),
                addmod(
                    mload(add(transcript, 0x7e0)),
                    mload(add(transcript, 0x1ba0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1be0),
                addmod(
                    mload(add(transcript, 0x1bc0)),
                    mload(add(transcript, 0x2c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c00),
                mulmod(
                    4131629893567559867359510883348571134090853742863529169391034518566172092834,
                    mload(add(transcript, 0x260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c20),
                mulmod(
                    mload(add(transcript, 0x580)),
                    mload(add(transcript, 0x1c00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c40),
                addmod(
                    mload(add(transcript, 0x5c0)),
                    mload(add(transcript, 0x1c20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c60),
                addmod(
                    mload(add(transcript, 0x1c40)),
                    mload(add(transcript, 0x2c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c80),
                mulmod(
                    mload(add(transcript, 0x1c60)),
                    mload(add(transcript, 0x1be0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ca0),
                mulmod(
                    mload(add(transcript, 0x1c80)),
                    mload(add(transcript, 0x980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1cc0),
                addmod(
                    mload(add(transcript, 0x1b60)),
                    sub(f_q, mload(add(transcript, 0x1ca0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ce0),
                mulmod(
                    mload(add(transcript, 0x1cc0)),
                    mload(add(transcript, 0x1a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d00),
                addmod(
                    mload(add(transcript, 0x1980)),
                    mload(add(transcript, 0x1ce0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d20),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x1d00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d40),
                mulmod(
                    mload(add(transcript, 0x900)),
                    mload(add(transcript, 0x260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d60),
                addmod(
                    mload(add(transcript, 0x640)),
                    mload(add(transcript, 0x1d40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d80),
                addmod(
                    mload(add(transcript, 0x1d60)),
                    mload(add(transcript, 0x2c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1da0),
                mulmod(
                    mload(add(transcript, 0x920)),
                    mload(add(transcript, 0x260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1dc0),
                addmod(
                    mload(add(transcript, 0x6c0)),
                    mload(add(transcript, 0x1da0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1de0),
                addmod(
                    mload(add(transcript, 0x1dc0)),
                    mload(add(transcript, 0x2c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1e00),
                mulmod(
                    mload(add(transcript, 0x1de0)),
                    mload(add(transcript, 0x1d80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1e20),
                mulmod(
                    mload(add(transcript, 0x1e00)),
                    mload(add(transcript, 0xa00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1e40),
                mulmod(
                    8910878055287538404433155982483128285667088683464058436815641868457422632747,
                    mload(add(transcript, 0x260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1e60),
                mulmod(
                    mload(add(transcript, 0x580)),
                    mload(add(transcript, 0x1e40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1e80),
                addmod(
                    mload(add(transcript, 0x640)),
                    mload(add(transcript, 0x1e60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ea0),
                addmod(
                    mload(add(transcript, 0x1e80)),
                    mload(add(transcript, 0x2c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ec0),
                mulmod(
                    11166246659983828508719468090013646171463329086121580628794302409516816350802,
                    mload(add(transcript, 0x260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ee0),
                mulmod(
                    mload(add(transcript, 0x580)),
                    mload(add(transcript, 0x1ec0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1f00),
                addmod(
                    mload(add(transcript, 0x6c0)),
                    mload(add(transcript, 0x1ee0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1f20),
                addmod(
                    mload(add(transcript, 0x1f00)),
                    mload(add(transcript, 0x2c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1f40),
                mulmod(
                    mload(add(transcript, 0x1f20)),
                    mload(add(transcript, 0x1ea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1f60),
                mulmod(
                    mload(add(transcript, 0x1f40)),
                    mload(add(transcript, 0x9e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1f80),
                addmod(
                    mload(add(transcript, 0x1e20)),
                    sub(f_q, mload(add(transcript, 0x1f60))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1fa0),
                mulmod(
                    mload(add(transcript, 0x1f80)),
                    mload(add(transcript, 0x1a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1fc0),
                addmod(
                    mload(add(transcript, 0x1d20)),
                    mload(add(transcript, 0x1fa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1fe0),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x1fc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2000),
                mulmod(
                    mload(add(transcript, 0x940)),
                    mload(add(transcript, 0x260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2020),
                addmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x2000)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2040),
                addmod(
                    mload(add(transcript, 0x2020)),
                    mload(add(transcript, 0x2c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2060),
                mulmod(
                    mload(add(transcript, 0x960)),
                    mload(add(transcript, 0x260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2080),
                addmod(
                    mload(add(transcript, 0x7c0)),
                    mload(add(transcript, 0x2060)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x20a0),
                addmod(
                    mload(add(transcript, 0x2080)),
                    mload(add(transcript, 0x2c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x20c0),
                mulmod(
                    mload(add(transcript, 0x20a0)),
                    mload(add(transcript, 0x2040)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x20e0),
                mulmod(
                    mload(add(transcript, 0x20c0)),
                    mload(add(transcript, 0xa60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2100),
                mulmod(
                    284840088355319032285349970403338060113257071685626700086398481893096618818,
                    mload(add(transcript, 0x260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2120),
                mulmod(
                    mload(add(transcript, 0x580)),
                    mload(add(transcript, 0x2100)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2140),
                addmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x2120)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2160),
                addmod(
                    mload(add(transcript, 0x2140)),
                    mload(add(transcript, 0x2c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2180),
                mulmod(
                    21134065618345176623193549882539580312263652408302468683943992798037078993309,
                    mload(add(transcript, 0x260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21a0),
                mulmod(
                    mload(add(transcript, 0x580)),
                    mload(add(transcript, 0x2180)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21c0),
                addmod(
                    mload(add(transcript, 0x7c0)),
                    mload(add(transcript, 0x21a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21e0),
                addmod(
                    mload(add(transcript, 0x21c0)),
                    mload(add(transcript, 0x2c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2200),
                mulmod(
                    mload(add(transcript, 0x21e0)),
                    mload(add(transcript, 0x2160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2220),
                mulmod(
                    mload(add(transcript, 0x2200)),
                    mload(add(transcript, 0xa40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2240),
                addmod(
                    mload(add(transcript, 0x20e0)),
                    sub(f_q, mload(add(transcript, 0x2220))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2260),
                mulmod(
                    mload(add(transcript, 0x2240)),
                    mload(add(transcript, 0x1a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2280),
                addmod(
                    mload(add(transcript, 0x1fe0)),
                    mload(add(transcript, 0x2260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22a0),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x2280)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22c0),
                addmod(1, sub(f_q, mload(add(transcript, 0xa80))), f_q)
            )
            mstore(
                add(transcript, 0x22e0),
                mulmod(
                    mload(add(transcript, 0x22c0)),
                    mload(add(transcript, 0x1480)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2300),
                addmod(
                    mload(add(transcript, 0x22a0)),
                    mload(add(transcript, 0x22e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2320),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x2300)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2340),
                mulmod(
                    mload(add(transcript, 0xa80)),
                    mload(add(transcript, 0xa80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2360),
                addmod(
                    mload(add(transcript, 0x2340)),
                    sub(f_q, mload(add(transcript, 0xa80))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2380),
                mulmod(
                    mload(add(transcript, 0x2360)),
                    mload(add(transcript, 0x13a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x23a0),
                addmod(
                    mload(add(transcript, 0x2320)),
                    mload(add(transcript, 0x2380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x23c0),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x23a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x23e0),
                addmod(
                    mload(add(transcript, 0xac0)),
                    mload(add(transcript, 0x260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2400),
                mulmod(
                    mload(add(transcript, 0x23e0)),
                    mload(add(transcript, 0xaa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2420),
                addmod(
                    mload(add(transcript, 0xb00)),
                    mload(add(transcript, 0x2c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2440),
                mulmod(
                    mload(add(transcript, 0x2420)),
                    mload(add(transcript, 0x2400)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2460),
                addmod(
                    mload(add(transcript, 0x7c0)),
                    mload(add(transcript, 0x260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2480),
                mulmod(
                    mload(add(transcript, 0x2460)),
                    mload(add(transcript, 0xa80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24a0),
                addmod(
                    mload(add(transcript, 0x800)),
                    mload(add(transcript, 0x2c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24c0),
                mulmod(
                    mload(add(transcript, 0x24a0)),
                    mload(add(transcript, 0x2480)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24e0),
                addmod(
                    mload(add(transcript, 0x2440)),
                    sub(f_q, mload(add(transcript, 0x24c0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2500),
                mulmod(
                    mload(add(transcript, 0x24e0)),
                    mload(add(transcript, 0x1a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2520),
                addmod(
                    mload(add(transcript, 0x23c0)),
                    mload(add(transcript, 0x2500)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2540),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x2520)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2560),
                addmod(
                    mload(add(transcript, 0xac0)),
                    sub(f_q, mload(add(transcript, 0xb00))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2580),
                mulmod(
                    mload(add(transcript, 0x2560)),
                    mload(add(transcript, 0x1480)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25a0),
                addmod(
                    mload(add(transcript, 0x2540)),
                    mload(add(transcript, 0x2580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25c0),
                mulmod(
                    mload(add(transcript, 0x460)),
                    mload(add(transcript, 0x25a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25e0),
                mulmod(
                    mload(add(transcript, 0x2560)),
                    mload(add(transcript, 0x1a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2600),
                addmod(
                    mload(add(transcript, 0xac0)),
                    sub(f_q, mload(add(transcript, 0xae0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2620),
                mulmod(
                    mload(add(transcript, 0x2600)),
                    mload(add(transcript, 0x25e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2640),
                addmod(
                    mload(add(transcript, 0x25c0)),
                    mload(add(transcript, 0x2620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2660),
                mulmod(
                    mload(add(transcript, 0xf60)),
                    mload(add(transcript, 0xf60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2680),
                mulmod(
                    mload(add(transcript, 0x2660)),
                    mload(add(transcript, 0xf60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26a0),
                mulmod(1, mload(add(transcript, 0xf60)), f_q)
            )
            mstore(
                add(transcript, 0x26c0),
                mulmod(1, mload(add(transcript, 0x2660)), f_q)
            )
            mstore(
                add(transcript, 0x26e0),
                mulmod(
                    mload(add(transcript, 0x2640)),
                    mload(add(transcript, 0xf80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2700),
                mulmod(
                    mload(add(transcript, 0xd20)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2720),
                mulmod(
                    mload(add(transcript, 0x2700)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2740),
                mulmod(
                    mload(add(transcript, 0x2720)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2760),
                mulmod(
                    mload(add(transcript, 0x2740)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2780),
                mulmod(
                    mload(add(transcript, 0x2760)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x27a0),
                mulmod(
                    mload(add(transcript, 0xb40)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x27c0),
                mulmod(
                    mload(add(transcript, 0x27a0)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x27e0),
                mulmod(
                    mload(add(transcript, 0x27c0)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2800),
                mulmod(
                    mload(add(transcript, 0x27e0)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2820),
                mulmod(
                    mload(add(transcript, 0x2800)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2840),
                mulmod(
                    mload(add(transcript, 0x2820)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2860),
                mulmod(
                    mload(add(transcript, 0x2840)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2880),
                mulmod(
                    mload(add(transcript, 0x2860)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28a0),
                mulmod(
                    mload(add(transcript, 0x2880)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28c0),
                mulmod(
                    mload(add(transcript, 0x28a0)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28e0),
                mulmod(
                    mload(add(transcript, 0x28c0)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2900),
                mulmod(
                    mload(add(transcript, 0x28e0)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2920),
                mulmod(
                    mload(add(transcript, 0x2900)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2940),
                mulmod(
                    mload(add(transcript, 0x2920)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2960),
                mulmod(
                    mload(add(transcript, 0x2940)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2980),
                mulmod(
                    mload(add(transcript, 0x2960)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29a0),
                mulmod(
                    mload(add(transcript, 0x2980)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29c0),
                mulmod(
                    mload(add(transcript, 0x29a0)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29e0),
                mulmod(
                    mload(add(transcript, 0x29c0)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a00),
                mulmod(
                    mload(add(transcript, 0x29e0)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a20),
                mulmod(
                    mload(add(transcript, 0x2a00)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a40),
                mulmod(
                    mload(add(transcript, 0x2a20)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a60),
                mulmod(
                    mload(add(transcript, 0x2a40)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a80),
                mulmod(
                    mload(add(transcript, 0x2a60)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2aa0),
                mulmod(sub(f_q, mload(add(transcript, 0x5c0))), 1, f_q)
            )
            mstore(
                add(transcript, 0x2ac0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x640))),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ae0),
                mulmod(1, mload(add(transcript, 0xb40)), f_q)
            )
            mstore(
                add(transcript, 0x2b00),
                addmod(
                    mload(add(transcript, 0x2aa0)),
                    mload(add(transcript, 0x2ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b20),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x6c0))),
                    mload(add(transcript, 0x27a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b40),
                mulmod(1, mload(add(transcript, 0x27a0)), f_q)
            )
            mstore(
                add(transcript, 0x2b60),
                addmod(
                    mload(add(transcript, 0x2b00)),
                    mload(add(transcript, 0x2b20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b80),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x740))),
                    mload(add(transcript, 0x27c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ba0),
                mulmod(1, mload(add(transcript, 0x27c0)), f_q)
            )
            mstore(
                add(transcript, 0x2bc0),
                addmod(
                    mload(add(transcript, 0x2b60)),
                    mload(add(transcript, 0x2b80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2be0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x7c0))),
                    mload(add(transcript, 0x27e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c00),
                mulmod(1, mload(add(transcript, 0x27e0)), f_q)
            )
            mstore(
                add(transcript, 0x2c20),
                addmod(
                    mload(add(transcript, 0x2bc0)),
                    mload(add(transcript, 0x2be0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c40),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x980))),
                    mload(add(transcript, 0x2800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c60),
                mulmod(1, mload(add(transcript, 0x2800)), f_q)
            )
            mstore(
                add(transcript, 0x2c80),
                addmod(
                    mload(add(transcript, 0x2c20)),
                    mload(add(transcript, 0x2c40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ca0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x9e0))),
                    mload(add(transcript, 0x2820)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2cc0),
                mulmod(1, mload(add(transcript, 0x2820)), f_q)
            )
            mstore(
                add(transcript, 0x2ce0),
                addmod(
                    mload(add(transcript, 0x2c80)),
                    mload(add(transcript, 0x2ca0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d00),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xa40))),
                    mload(add(transcript, 0x2840)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d20),
                mulmod(1, mload(add(transcript, 0x2840)), f_q)
            )
            mstore(
                add(transcript, 0x2d40),
                addmod(
                    mload(add(transcript, 0x2ce0)),
                    mload(add(transcript, 0x2d00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d60),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xa80))),
                    mload(add(transcript, 0x2860)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d80),
                mulmod(1, mload(add(transcript, 0x2860)), f_q)
            )
            mstore(
                add(transcript, 0x2da0),
                addmod(
                    mload(add(transcript, 0x2d40)),
                    mload(add(transcript, 0x2d60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2dc0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xac0))),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2de0),
                mulmod(1, mload(add(transcript, 0x2880)), f_q)
            )
            mstore(
                add(transcript, 0x2e00),
                addmod(
                    mload(add(transcript, 0x2da0)),
                    mload(add(transcript, 0x2dc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e20),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xb00))),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e40),
                mulmod(1, mload(add(transcript, 0x28a0)), f_q)
            )
            mstore(
                add(transcript, 0x2e60),
                addmod(
                    mload(add(transcript, 0x2e00)),
                    mload(add(transcript, 0x2e20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e80),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x7e0))),
                    mload(add(transcript, 0x28c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ea0),
                mulmod(1, mload(add(transcript, 0x28c0)), f_q)
            )
            mstore(
                add(transcript, 0x2ec0),
                addmod(
                    mload(add(transcript, 0x2e60)),
                    mload(add(transcript, 0x2e80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ee0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x800))),
                    mload(add(transcript, 0x28e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f00),
                mulmod(1, mload(add(transcript, 0x28e0)), f_q)
            )
            mstore(
                add(transcript, 0x2f20),
                addmod(
                    mload(add(transcript, 0x2ec0)),
                    mload(add(transcript, 0x2ee0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f40),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x820))),
                    mload(add(transcript, 0x2900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f60),
                mulmod(1, mload(add(transcript, 0x2900)), f_q)
            )
            mstore(
                add(transcript, 0x2f80),
                addmod(
                    mload(add(transcript, 0x2f20)),
                    mload(add(transcript, 0x2f40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2fa0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x840))),
                    mload(add(transcript, 0x2920)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2fc0),
                mulmod(1, mload(add(transcript, 0x2920)), f_q)
            )
            mstore(
                add(transcript, 0x2fe0),
                addmod(
                    mload(add(transcript, 0x2f80)),
                    mload(add(transcript, 0x2fa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3000),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x860))),
                    mload(add(transcript, 0x2940)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3020),
                mulmod(1, mload(add(transcript, 0x2940)), f_q)
            )
            mstore(
                add(transcript, 0x3040),
                addmod(
                    mload(add(transcript, 0x2fe0)),
                    mload(add(transcript, 0x3000)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3060),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x880))),
                    mload(add(transcript, 0x2960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3080),
                mulmod(1, mload(add(transcript, 0x2960)), f_q)
            )
            mstore(
                add(transcript, 0x30a0),
                addmod(
                    mload(add(transcript, 0x3040)),
                    mload(add(transcript, 0x3060)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x30c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x8c0))),
                    mload(add(transcript, 0x2980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x30e0),
                mulmod(1, mload(add(transcript, 0x2980)), f_q)
            )
            mstore(
                add(transcript, 0x3100),
                addmod(
                    mload(add(transcript, 0x30a0)),
                    mload(add(transcript, 0x30c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3120),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x8e0))),
                    mload(add(transcript, 0x29a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3140),
                mulmod(1, mload(add(transcript, 0x29a0)), f_q)
            )
            mstore(
                add(transcript, 0x3160),
                addmod(
                    mload(add(transcript, 0x3100)),
                    mload(add(transcript, 0x3120)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3180),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x900))),
                    mload(add(transcript, 0x29c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x31a0),
                mulmod(1, mload(add(transcript, 0x29c0)), f_q)
            )
            mstore(
                add(transcript, 0x31c0),
                addmod(
                    mload(add(transcript, 0x3160)),
                    mload(add(transcript, 0x3180)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x31e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x920))),
                    mload(add(transcript, 0x29e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3200),
                mulmod(1, mload(add(transcript, 0x29e0)), f_q)
            )
            mstore(
                add(transcript, 0x3220),
                addmod(
                    mload(add(transcript, 0x31c0)),
                    mload(add(transcript, 0x31e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3240),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x940))),
                    mload(add(transcript, 0x2a00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3260),
                mulmod(1, mload(add(transcript, 0x2a00)), f_q)
            )
            mstore(
                add(transcript, 0x3280),
                addmod(
                    mload(add(transcript, 0x3220)),
                    mload(add(transcript, 0x3240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x32a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x960))),
                    mload(add(transcript, 0x2a20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x32c0),
                mulmod(1, mload(add(transcript, 0x2a20)), f_q)
            )
            mstore(
                add(transcript, 0x32e0),
                addmod(
                    mload(add(transcript, 0x3280)),
                    mload(add(transcript, 0x32a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3300),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x26e0))),
                    mload(add(transcript, 0x2a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3320),
                mulmod(1, mload(add(transcript, 0x2a40)), f_q)
            )
            mstore(
                add(transcript, 0x3340),
                mulmod(
                    mload(add(transcript, 0x26a0)),
                    mload(add(transcript, 0x2a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3360),
                mulmod(
                    mload(add(transcript, 0x26c0)),
                    mload(add(transcript, 0x2a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3380),
                addmod(
                    mload(add(transcript, 0x32e0)),
                    mload(add(transcript, 0x3300)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x33a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x8a0))),
                    mload(add(transcript, 0x2a60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x33c0),
                mulmod(1, mload(add(transcript, 0x2a60)), f_q)
            )
            mstore(
                add(transcript, 0x33e0),
                addmod(
                    mload(add(transcript, 0x3380)),
                    mload(add(transcript, 0x33a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3400),
                mulmod(mload(add(transcript, 0x33e0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3420),
                mulmod(mload(add(transcript, 0x2ae0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3440),
                mulmod(mload(add(transcript, 0x2b40)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3460),
                mulmod(mload(add(transcript, 0x2ba0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3480),
                mulmod(mload(add(transcript, 0x2c00)), 1, f_q)
            )
            mstore(
                add(transcript, 0x34a0),
                mulmod(mload(add(transcript, 0x2c60)), 1, f_q)
            )
            mstore(
                add(transcript, 0x34c0),
                mulmod(mload(add(transcript, 0x2cc0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x34e0),
                mulmod(mload(add(transcript, 0x2d20)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3500),
                mulmod(mload(add(transcript, 0x2d80)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3520),
                mulmod(mload(add(transcript, 0x2de0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3540),
                mulmod(mload(add(transcript, 0x2e40)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3560),
                mulmod(mload(add(transcript, 0x2ea0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3580),
                mulmod(mload(add(transcript, 0x2f00)), 1, f_q)
            )
            mstore(
                add(transcript, 0x35a0),
                mulmod(mload(add(transcript, 0x2f60)), 1, f_q)
            )
            mstore(
                add(transcript, 0x35c0),
                mulmod(mload(add(transcript, 0x2fc0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x35e0),
                mulmod(mload(add(transcript, 0x3020)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3600),
                mulmod(mload(add(transcript, 0x3080)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3620),
                mulmod(mload(add(transcript, 0x30e0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3640),
                mulmod(mload(add(transcript, 0x3140)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3660),
                mulmod(mload(add(transcript, 0x31a0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3680),
                mulmod(mload(add(transcript, 0x3200)), 1, f_q)
            )
            mstore(
                add(transcript, 0x36a0),
                mulmod(mload(add(transcript, 0x3260)), 1, f_q)
            )
            mstore(
                add(transcript, 0x36c0),
                mulmod(mload(add(transcript, 0x32c0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x36e0),
                mulmod(mload(add(transcript, 0x3320)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3700),
                mulmod(mload(add(transcript, 0x3340)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3720),
                mulmod(mload(add(transcript, 0x3360)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3740),
                mulmod(mload(add(transcript, 0x33c0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3760),
                mulmod(sub(f_q, mload(add(transcript, 0x5e0))), 1, f_q)
            )
            mstore(
                add(transcript, 0x3780),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x660))),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x37a0),
                addmod(
                    mload(add(transcript, 0x3760)),
                    mload(add(transcript, 0x3780)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x37c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x6e0))),
                    mload(add(transcript, 0x27a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x37e0),
                addmod(
                    mload(add(transcript, 0x37a0)),
                    mload(add(transcript, 0x37c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3800),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x760))),
                    mload(add(transcript, 0x27c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3820),
                addmod(
                    mload(add(transcript, 0x37e0)),
                    mload(add(transcript, 0x3800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3840),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x9a0))),
                    mload(add(transcript, 0x27e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3860),
                addmod(
                    mload(add(transcript, 0x3820)),
                    mload(add(transcript, 0x3840)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3880),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xa00))),
                    mload(add(transcript, 0x2800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x38a0),
                addmod(
                    mload(add(transcript, 0x3860)),
                    mload(add(transcript, 0x3880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x38c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xa60))),
                    mload(add(transcript, 0x2820)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x38e0),
                addmod(
                    mload(add(transcript, 0x38a0)),
                    mload(add(transcript, 0x38c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3900),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xaa0))),
                    mload(add(transcript, 0x2840)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3920),
                addmod(
                    mload(add(transcript, 0x38e0)),
                    mload(add(transcript, 0x3900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3940),
                mulmod(
                    mload(add(transcript, 0x3920)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3960),
                mulmod(1, mload(add(transcript, 0xd20)), f_q)
            )
            mstore(
                add(transcript, 0x3980),
                mulmod(
                    mload(add(transcript, 0x2ae0)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x39a0),
                mulmod(
                    mload(add(transcript, 0x2b40)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x39c0),
                mulmod(
                    mload(add(transcript, 0x2ba0)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x39e0),
                mulmod(
                    mload(add(transcript, 0x2c00)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a00),
                mulmod(
                    mload(add(transcript, 0x2c60)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a20),
                mulmod(
                    mload(add(transcript, 0x2cc0)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a40),
                mulmod(
                    mload(add(transcript, 0x2d20)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a60),
                addmod(
                    mload(add(transcript, 0x3400)),
                    mload(add(transcript, 0x3940)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3a80),
                addmod(1, mload(add(transcript, 0x3960)), f_q)
            )
            mstore(
                add(transcript, 0x3aa0),
                addmod(
                    mload(add(transcript, 0x3420)),
                    mload(add(transcript, 0x3980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ac0),
                addmod(
                    mload(add(transcript, 0x3440)),
                    mload(add(transcript, 0x39a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ae0),
                addmod(
                    mload(add(transcript, 0x3460)),
                    mload(add(transcript, 0x39c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b00),
                addmod(
                    mload(add(transcript, 0x34a0)),
                    mload(add(transcript, 0x39e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b20),
                addmod(
                    mload(add(transcript, 0x34c0)),
                    mload(add(transcript, 0x3a00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b40),
                addmod(
                    mload(add(transcript, 0x34e0)),
                    mload(add(transcript, 0x3a20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b60),
                addmod(
                    mload(add(transcript, 0x3500)),
                    mload(add(transcript, 0x3a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b80),
                mulmod(sub(f_q, mload(add(transcript, 0x600))), 1, f_q)
            )
            mstore(
                add(transcript, 0x3ba0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x680))),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3bc0),
                addmod(
                    mload(add(transcript, 0x3b80)),
                    mload(add(transcript, 0x3ba0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3be0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x700))),
                    mload(add(transcript, 0x27a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c00),
                addmod(
                    mload(add(transcript, 0x3bc0)),
                    mload(add(transcript, 0x3be0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c20),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x780))),
                    mload(add(transcript, 0x27c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c40),
                addmod(
                    mload(add(transcript, 0x3c00)),
                    mload(add(transcript, 0x3c20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c60),
                mulmod(
                    mload(add(transcript, 0x3c40)),
                    mload(add(transcript, 0x2700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c80),
                mulmod(1, mload(add(transcript, 0x2700)), f_q)
            )
            mstore(
                add(transcript, 0x3ca0),
                mulmod(
                    mload(add(transcript, 0x2ae0)),
                    mload(add(transcript, 0x2700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3cc0),
                mulmod(
                    mload(add(transcript, 0x2b40)),
                    mload(add(transcript, 0x2700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ce0),
                mulmod(
                    mload(add(transcript, 0x2ba0)),
                    mload(add(transcript, 0x2700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d00),
                addmod(
                    mload(add(transcript, 0x3a60)),
                    mload(add(transcript, 0x3c60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d20),
                addmod(
                    mload(add(transcript, 0x3a80)),
                    mload(add(transcript, 0x3c80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d40),
                addmod(
                    mload(add(transcript, 0x3aa0)),
                    mload(add(transcript, 0x3ca0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d60),
                addmod(
                    mload(add(transcript, 0x3ac0)),
                    mload(add(transcript, 0x3cc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d80),
                addmod(
                    mload(add(transcript, 0x3ae0)),
                    mload(add(transcript, 0x3ce0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3da0),
                mulmod(sub(f_q, mload(add(transcript, 0x620))), 1, f_q)
            )
            mstore(
                add(transcript, 0x3dc0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x6a0))),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3de0),
                addmod(
                    mload(add(transcript, 0x3da0)),
                    mload(add(transcript, 0x3dc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e00),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x720))),
                    mload(add(transcript, 0x27a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e20),
                addmod(
                    mload(add(transcript, 0x3de0)),
                    mload(add(transcript, 0x3e00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e40),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x7a0))),
                    mload(add(transcript, 0x27c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e60),
                addmod(
                    mload(add(transcript, 0x3e20)),
                    mload(add(transcript, 0x3e40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e80),
                mulmod(
                    mload(add(transcript, 0x3e60)),
                    mload(add(transcript, 0x2720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ea0),
                mulmod(1, mload(add(transcript, 0x2720)), f_q)
            )
            mstore(
                add(transcript, 0x3ec0),
                mulmod(
                    mload(add(transcript, 0x2ae0)),
                    mload(add(transcript, 0x2720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ee0),
                mulmod(
                    mload(add(transcript, 0x2b40)),
                    mload(add(transcript, 0x2720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f00),
                mulmod(
                    mload(add(transcript, 0x2ba0)),
                    mload(add(transcript, 0x2720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f20),
                addmod(
                    mload(add(transcript, 0x3d00)),
                    mload(add(transcript, 0x3e80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f40),
                addmod(
                    mload(add(transcript, 0x3d20)),
                    mload(add(transcript, 0x3ea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f60),
                addmod(
                    mload(add(transcript, 0x3d40)),
                    mload(add(transcript, 0x3ec0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f80),
                addmod(
                    mload(add(transcript, 0x3d60)),
                    mload(add(transcript, 0x3ee0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3fa0),
                addmod(
                    mload(add(transcript, 0x3d80)),
                    mload(add(transcript, 0x3f00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3fc0),
                mulmod(sub(f_q, mload(add(transcript, 0xa20))), 1, f_q)
            )
            mstore(
                add(transcript, 0x3fe0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x9c0))),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4000),
                addmod(
                    mload(add(transcript, 0x3fc0)),
                    mload(add(transcript, 0x3fe0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4020),
                mulmod(
                    mload(add(transcript, 0x4000)),
                    mload(add(transcript, 0x2740)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4040),
                mulmod(1, mload(add(transcript, 0x2740)), f_q)
            )
            mstore(
                add(transcript, 0x4060),
                mulmod(
                    mload(add(transcript, 0x2ae0)),
                    mload(add(transcript, 0x2740)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4080),
                addmod(
                    mload(add(transcript, 0x3f20)),
                    mload(add(transcript, 0x4020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x40a0),
                addmod(
                    mload(add(transcript, 0x3b20)),
                    mload(add(transcript, 0x4040)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x40c0),
                addmod(
                    mload(add(transcript, 0x3b00)),
                    mload(add(transcript, 0x4060)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x40e0),
                mulmod(sub(f_q, mload(add(transcript, 0xae0))), 1, f_q)
            )
            mstore(
                add(transcript, 0x4100),
                mulmod(
                    mload(add(transcript, 0x40e0)),
                    mload(add(transcript, 0x2760)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4120),
                mulmod(1, mload(add(transcript, 0x2760)), f_q)
            )
            mstore(
                add(transcript, 0x4140),
                addmod(
                    mload(add(transcript, 0x4080)),
                    mload(add(transcript, 0x4100)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4160),
                addmod(
                    mload(add(transcript, 0x3520)),
                    mload(add(transcript, 0x4120)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4180),
                mulmod(1, mload(add(transcript, 0x580)), f_q)
            )
            mstore(
                add(transcript, 0x41a0),
                mulmod(1, mload(add(transcript, 0x4180)), f_q)
            )
            mstore(
                add(transcript, 0x41c0),
                mulmod(
                    21846745818185811051373434299876022191132089169516983080959277716660228899818,
                    mload(add(transcript, 0x580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x41e0),
                mulmod(
                    mload(add(transcript, 0x3960)),
                    mload(add(transcript, 0x41c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4200),
                mulmod(
                    4443263508319656594054352481848447997537391617204595126809744742387004492585,
                    mload(add(transcript, 0x580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4220),
                mulmod(
                    mload(add(transcript, 0x3c80)),
                    mload(add(transcript, 0x4200)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4240),
                mulmod(
                    12491230264321380165669116208790466830459716800431293091713220204712467607643,
                    mload(add(transcript, 0x580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4260),
                mulmod(
                    mload(add(transcript, 0x3ea0)),
                    mload(add(transcript, 0x4240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4280),
                mulmod(
                    21180393220728113421338195116216869725258066600961496947533653125588029756005,
                    mload(add(transcript, 0x580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x42a0),
                mulmod(
                    mload(add(transcript, 0x4040)),
                    mload(add(transcript, 0x4280)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x42c0),
                mulmod(
                    11402394834529375719535454173347509224290498423785625657829583372803806900475,
                    mload(add(transcript, 0x580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x42e0),
                mulmod(
                    mload(add(transcript, 0x4120)),
                    mload(add(transcript, 0x42c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x4300),
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            mstore(
                add(transcript, 0x4320),
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            mstore(add(transcript, 0x4340), mload(add(transcript, 0x4140)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4300),
                        0x60,
                        add(transcript, 0x4300),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4360), mload(add(transcript, 0x20)))
            mstore(add(transcript, 0x4380), mload(add(transcript, 0x40)))
            mstore(add(transcript, 0x43a0), mload(add(transcript, 0x3f40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4360),
                        0x60,
                        add(transcript, 0x4360),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x43c0), mload(add(transcript, 0x4300)))
            mstore(add(transcript, 0x43e0), mload(add(transcript, 0x4320)))
            mstore(add(transcript, 0x4400), mload(add(transcript, 0x4360)))
            mstore(add(transcript, 0x4420), mload(add(transcript, 0x4380)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x43c0),
                        0x80,
                        add(transcript, 0x43c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4440), mload(add(transcript, 0x60)))
            mstore(add(transcript, 0x4460), mload(add(transcript, 0x80)))
            mstore(add(transcript, 0x4480), mload(add(transcript, 0x3f60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4440),
                        0x60,
                        add(transcript, 0x4440),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x44a0), mload(add(transcript, 0x43c0)))
            mstore(add(transcript, 0x44c0), mload(add(transcript, 0x43e0)))
            mstore(add(transcript, 0x44e0), mload(add(transcript, 0x4440)))
            mstore(add(transcript, 0x4500), mload(add(transcript, 0x4460)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x44a0),
                        0x80,
                        add(transcript, 0x44a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4520), mload(add(transcript, 0xa0)))
            mstore(add(transcript, 0x4540), mload(add(transcript, 0xc0)))
            mstore(add(transcript, 0x4560), mload(add(transcript, 0x3f80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4520),
                        0x60,
                        add(transcript, 0x4520),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4580), mload(add(transcript, 0x44a0)))
            mstore(add(transcript, 0x45a0), mload(add(transcript, 0x44c0)))
            mstore(add(transcript, 0x45c0), mload(add(transcript, 0x4520)))
            mstore(add(transcript, 0x45e0), mload(add(transcript, 0x4540)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4580),
                        0x80,
                        add(transcript, 0x4580),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4600), mload(add(transcript, 0xe0)))
            mstore(add(transcript, 0x4620), mload(add(transcript, 0x100)))
            mstore(add(transcript, 0x4640), mload(add(transcript, 0x3fa0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4600),
                        0x60,
                        add(transcript, 0x4600),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4660), mload(add(transcript, 0x4580)))
            mstore(add(transcript, 0x4680), mload(add(transcript, 0x45a0)))
            mstore(add(transcript, 0x46a0), mload(add(transcript, 0x4600)))
            mstore(add(transcript, 0x46c0), mload(add(transcript, 0x4620)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4660),
                        0x80,
                        add(transcript, 0x4660),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x46e0), mload(add(transcript, 0x120)))
            mstore(add(transcript, 0x4700), mload(add(transcript, 0x140)))
            mstore(add(transcript, 0x4720), mload(add(transcript, 0x3480)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x46e0),
                        0x60,
                        add(transcript, 0x46e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4740), mload(add(transcript, 0x4660)))
            mstore(add(transcript, 0x4760), mload(add(transcript, 0x4680)))
            mstore(add(transcript, 0x4780), mload(add(transcript, 0x46e0)))
            mstore(add(transcript, 0x47a0), mload(add(transcript, 0x4700)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4740),
                        0x80,
                        add(transcript, 0x4740),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x47c0), mload(add(transcript, 0x300)))
            mstore(add(transcript, 0x47e0), mload(add(transcript, 0x320)))
            mstore(add(transcript, 0x4800), mload(add(transcript, 0x40c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x47c0),
                        0x60,
                        add(transcript, 0x47c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4820), mload(add(transcript, 0x4740)))
            mstore(add(transcript, 0x4840), mload(add(transcript, 0x4760)))
            mstore(add(transcript, 0x4860), mload(add(transcript, 0x47c0)))
            mstore(add(transcript, 0x4880), mload(add(transcript, 0x47e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4820),
                        0x80,
                        add(transcript, 0x4820),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x48a0), mload(add(transcript, 0x340)))
            mstore(add(transcript, 0x48c0), mload(add(transcript, 0x360)))
            mstore(add(transcript, 0x48e0), mload(add(transcript, 0x40a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x48a0),
                        0x60,
                        add(transcript, 0x48a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4900), mload(add(transcript, 0x4820)))
            mstore(add(transcript, 0x4920), mload(add(transcript, 0x4840)))
            mstore(add(transcript, 0x4940), mload(add(transcript, 0x48a0)))
            mstore(add(transcript, 0x4960), mload(add(transcript, 0x48c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4900),
                        0x80,
                        add(transcript, 0x4900),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4980), mload(add(transcript, 0x380)))
            mstore(add(transcript, 0x49a0), mload(add(transcript, 0x3a0)))
            mstore(add(transcript, 0x49c0), mload(add(transcript, 0x3b40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4980),
                        0x60,
                        add(transcript, 0x4980),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x49e0), mload(add(transcript, 0x4900)))
            mstore(add(transcript, 0x4a00), mload(add(transcript, 0x4920)))
            mstore(add(transcript, 0x4a20), mload(add(transcript, 0x4980)))
            mstore(add(transcript, 0x4a40), mload(add(transcript, 0x49a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x49e0),
                        0x80,
                        add(transcript, 0x49e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4a60), mload(add(transcript, 0x3c0)))
            mstore(add(transcript, 0x4a80), mload(add(transcript, 0x3e0)))
            mstore(add(transcript, 0x4aa0), mload(add(transcript, 0x3b60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4a60),
                        0x60,
                        add(transcript, 0x4a60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4ac0), mload(add(transcript, 0x49e0)))
            mstore(add(transcript, 0x4ae0), mload(add(transcript, 0x4a00)))
            mstore(add(transcript, 0x4b00), mload(add(transcript, 0x4a60)))
            mstore(add(transcript, 0x4b20), mload(add(transcript, 0x4a80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4ac0),
                        0x80,
                        add(transcript, 0x4ac0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4b40), mload(add(transcript, 0x1c0)))
            mstore(add(transcript, 0x4b60), mload(add(transcript, 0x1e0)))
            mstore(add(transcript, 0x4b80), mload(add(transcript, 0x4160)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4b40),
                        0x60,
                        add(transcript, 0x4b40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4ba0), mload(add(transcript, 0x4ac0)))
            mstore(add(transcript, 0x4bc0), mload(add(transcript, 0x4ae0)))
            mstore(add(transcript, 0x4be0), mload(add(transcript, 0x4b40)))
            mstore(add(transcript, 0x4c00), mload(add(transcript, 0x4b60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4ba0),
                        0x80,
                        add(transcript, 0x4ba0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4c20), mload(add(transcript, 0x200)))
            mstore(add(transcript, 0x4c40), mload(add(transcript, 0x220)))
            mstore(add(transcript, 0x4c60), mload(add(transcript, 0x3540)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4c20),
                        0x60,
                        add(transcript, 0x4c20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4c80), mload(add(transcript, 0x4ba0)))
            mstore(add(transcript, 0x4ca0), mload(add(transcript, 0x4bc0)))
            mstore(add(transcript, 0x4cc0), mload(add(transcript, 0x4c20)))
            mstore(add(transcript, 0x4ce0), mload(add(transcript, 0x4c40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4c80),
                        0x80,
                        add(transcript, 0x4c80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x4d00),
                0x0dff8d04331a85b6120dc7c6931fc454e9037c9b93e38a4f71aa5fd9fe75bc97
            )
            mstore(
                add(transcript, 0x4d20),
                0x14bd60e4170e4bbe0b1e1e4d15b2d437df5866b83fcafe0753749e17d75c2cd9
            )
            mstore(add(transcript, 0x4d40), mload(add(transcript, 0x3560)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4d00),
                        0x60,
                        add(transcript, 0x4d00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4d60), mload(add(transcript, 0x4c80)))
            mstore(add(transcript, 0x4d80), mload(add(transcript, 0x4ca0)))
            mstore(add(transcript, 0x4da0), mload(add(transcript, 0x4d00)))
            mstore(add(transcript, 0x4dc0), mload(add(transcript, 0x4d20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4d60),
                        0x80,
                        add(transcript, 0x4d60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x4de0),
                0x2f579160607cc547a54ef72e5a1a2966a65305c955cf8d94f507169386a10f4c
            )
            mstore(
                add(transcript, 0x4e00),
                0x15932d491aaaa6d3673eeb19941a96ee53b011a6923028a70466a155b753d46b
            )
            mstore(add(transcript, 0x4e20), mload(add(transcript, 0x3580)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4de0),
                        0x60,
                        add(transcript, 0x4de0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4e40), mload(add(transcript, 0x4d60)))
            mstore(add(transcript, 0x4e60), mload(add(transcript, 0x4d80)))
            mstore(add(transcript, 0x4e80), mload(add(transcript, 0x4de0)))
            mstore(add(transcript, 0x4ea0), mload(add(transcript, 0x4e00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4e40),
                        0x80,
                        add(transcript, 0x4e40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x4ec0),
                0x11296fee9462167f3654dc994f115d276f9341f4a09938e8709c254b45a8184e
            )
            mstore(
                add(transcript, 0x4ee0),
                0x0073a5ff1d83202c85f53e39701a5b81e120e34d4144c3685628f11fe600d1c8
            )
            mstore(add(transcript, 0x4f00), mload(add(transcript, 0x35a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4ec0),
                        0x60,
                        add(transcript, 0x4ec0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4f20), mload(add(transcript, 0x4e40)))
            mstore(add(transcript, 0x4f40), mload(add(transcript, 0x4e60)))
            mstore(add(transcript, 0x4f60), mload(add(transcript, 0x4ec0)))
            mstore(add(transcript, 0x4f80), mload(add(transcript, 0x4ee0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4f20),
                        0x80,
                        add(transcript, 0x4f20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x4fa0),
                0x24a62d386c435b4fde43b1101de79c96bdcab6e4c3c27d64a84dd7cdf40a19cd
            )
            mstore(
                add(transcript, 0x4fc0),
                0x28baaa1cd3c8564f7592474e70b2be39f920e563f2653f1a468e44750fee28fc
            )
            mstore(add(transcript, 0x4fe0), mload(add(transcript, 0x35c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4fa0),
                        0x60,
                        add(transcript, 0x4fa0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5000), mload(add(transcript, 0x4f20)))
            mstore(add(transcript, 0x5020), mload(add(transcript, 0x4f40)))
            mstore(add(transcript, 0x5040), mload(add(transcript, 0x4fa0)))
            mstore(add(transcript, 0x5060), mload(add(transcript, 0x4fc0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5000),
                        0x80,
                        add(transcript, 0x5000),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x5080),
                0x2f5dc887b3e303b298a275a19cc20346f4ea520da08559fba986ed9705c94ca5
            )
            mstore(
                add(transcript, 0x50a0),
                0x21be9078a0b99102948250140813cc1731845eeb648e8b8638b33e995d426a25
            )
            mstore(add(transcript, 0x50c0), mload(add(transcript, 0x35e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5080),
                        0x60,
                        add(transcript, 0x5080),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x50e0), mload(add(transcript, 0x5000)))
            mstore(add(transcript, 0x5100), mload(add(transcript, 0x5020)))
            mstore(add(transcript, 0x5120), mload(add(transcript, 0x5080)))
            mstore(add(transcript, 0x5140), mload(add(transcript, 0x50a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x50e0),
                        0x80,
                        add(transcript, 0x50e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x5160),
                0x2a0677efd45c4ab5d3b792b8fd045a67cf59648d08b62595b7f88dd5d05aee33
            )
            mstore(
                add(transcript, 0x5180),
                0x03ee72dc1dae3d5b618521ea55fe56626e5cda6d307ca649d571a94b3ef7bc87
            )
            mstore(add(transcript, 0x51a0), mload(add(transcript, 0x3600)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5160),
                        0x60,
                        add(transcript, 0x5160),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x51c0), mload(add(transcript, 0x50e0)))
            mstore(add(transcript, 0x51e0), mload(add(transcript, 0x5100)))
            mstore(add(transcript, 0x5200), mload(add(transcript, 0x5160)))
            mstore(add(transcript, 0x5220), mload(add(transcript, 0x5180)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x51c0),
                        0x80,
                        add(transcript, 0x51c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x5240),
                0x0c11bdfa7a12ca0606d461516b1812be1116d7ff14f7dd6de65aaa982a607acf
            )
            mstore(
                add(transcript, 0x5260),
                0x06acc27ceaaa3e95505f13892883f8521adedc9bbd43598e868a17f02ae33625
            )
            mstore(add(transcript, 0x5280), mload(add(transcript, 0x3620)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5240),
                        0x60,
                        add(transcript, 0x5240),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x52a0), mload(add(transcript, 0x51c0)))
            mstore(add(transcript, 0x52c0), mload(add(transcript, 0x51e0)))
            mstore(add(transcript, 0x52e0), mload(add(transcript, 0x5240)))
            mstore(add(transcript, 0x5300), mload(add(transcript, 0x5260)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x52a0),
                        0x80,
                        add(transcript, 0x52a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x5320),
                0x22304e7bee3c7aff8297144af6ea0c074de44a927d8752e0d9c7b45b1f05fccd
            )
            mstore(
                add(transcript, 0x5340),
                0x2f1313f85baf7c33b5f9ed033721c82944d69e41390dd33da9513bd99676ca66
            )
            mstore(add(transcript, 0x5360), mload(add(transcript, 0x3640)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5320),
                        0x60,
                        add(transcript, 0x5320),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5380), mload(add(transcript, 0x52a0)))
            mstore(add(transcript, 0x53a0), mload(add(transcript, 0x52c0)))
            mstore(add(transcript, 0x53c0), mload(add(transcript, 0x5320)))
            mstore(add(transcript, 0x53e0), mload(add(transcript, 0x5340)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5380),
                        0x80,
                        add(transcript, 0x5380),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x5400),
                0x1c708d04f001424ee7b2077673e84220c0fb42b5fffb2db82d818fa9d9b80c1e
            )
            mstore(
                add(transcript, 0x5420),
                0x0d4766ae417fe4d18b46fda1b18c8665b816f9b980fe37817a64937a4fce00e2
            )
            mstore(add(transcript, 0x5440), mload(add(transcript, 0x3660)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5400),
                        0x60,
                        add(transcript, 0x5400),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5460), mload(add(transcript, 0x5380)))
            mstore(add(transcript, 0x5480), mload(add(transcript, 0x53a0)))
            mstore(add(transcript, 0x54a0), mload(add(transcript, 0x5400)))
            mstore(add(transcript, 0x54c0), mload(add(transcript, 0x5420)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5460),
                        0x80,
                        add(transcript, 0x5460),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x54e0),
                0x14b76f83cf9e09d83b0fed71c64b7e4e7ed34e57b1ad256c037910dcc4e53bcc
            )
            mstore(
                add(transcript, 0x5500),
                0x00842333c00cdcf8cd03a588e7395720b824e2c8d7f83d34b3eaed2e5ed660cb
            )
            mstore(add(transcript, 0x5520), mload(add(transcript, 0x3680)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x54e0),
                        0x60,
                        add(transcript, 0x54e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5540), mload(add(transcript, 0x5460)))
            mstore(add(transcript, 0x5560), mload(add(transcript, 0x5480)))
            mstore(add(transcript, 0x5580), mload(add(transcript, 0x54e0)))
            mstore(add(transcript, 0x55a0), mload(add(transcript, 0x5500)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5540),
                        0x80,
                        add(transcript, 0x5540),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x55c0),
                0x1bd997cdf68f8cb6f57e1e6e1f1360170161786c9f9e7c68f107276b42c76576
            )
            mstore(
                add(transcript, 0x55e0),
                0x2d2df447a3729e8922d95dd626a7b3e43b2eeb91c9f8710af3915fc2ab4d52a5
            )
            mstore(add(transcript, 0x5600), mload(add(transcript, 0x36a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x55c0),
                        0x60,
                        add(transcript, 0x55c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5620), mload(add(transcript, 0x5540)))
            mstore(add(transcript, 0x5640), mload(add(transcript, 0x5560)))
            mstore(add(transcript, 0x5660), mload(add(transcript, 0x55c0)))
            mstore(add(transcript, 0x5680), mload(add(transcript, 0x55e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5620),
                        0x80,
                        add(transcript, 0x5620),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x56a0),
                0x2133d421c4f201a8c7d877c74d0036606e3d3fe700f25adca7f2fb9daeb2d578
            )
            mstore(
                add(transcript, 0x56c0),
                0x14ce0243e1d996a67c02c08537383b983b4f193a780cfdc5676f15a1fe8a0bbc
            )
            mstore(add(transcript, 0x56e0), mload(add(transcript, 0x36c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x56a0),
                        0x60,
                        add(transcript, 0x56a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5700), mload(add(transcript, 0x5620)))
            mstore(add(transcript, 0x5720), mload(add(transcript, 0x5640)))
            mstore(add(transcript, 0x5740), mload(add(transcript, 0x56a0)))
            mstore(add(transcript, 0x5760), mload(add(transcript, 0x56c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5700),
                        0x80,
                        add(transcript, 0x5700),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5780), mload(add(transcript, 0x4a0)))
            mstore(add(transcript, 0x57a0), mload(add(transcript, 0x4c0)))
            mstore(add(transcript, 0x57c0), mload(add(transcript, 0x36e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5780),
                        0x60,
                        add(transcript, 0x5780),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x57e0), mload(add(transcript, 0x5700)))
            mstore(add(transcript, 0x5800), mload(add(transcript, 0x5720)))
            mstore(add(transcript, 0x5820), mload(add(transcript, 0x5780)))
            mstore(add(transcript, 0x5840), mload(add(transcript, 0x57a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x57e0),
                        0x80,
                        add(transcript, 0x57e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5860), mload(add(transcript, 0x4e0)))
            mstore(add(transcript, 0x5880), mload(add(transcript, 0x500)))
            mstore(add(transcript, 0x58a0), mload(add(transcript, 0x3700)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5860),
                        0x60,
                        add(transcript, 0x5860),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x58c0), mload(add(transcript, 0x57e0)))
            mstore(add(transcript, 0x58e0), mload(add(transcript, 0x5800)))
            mstore(add(transcript, 0x5900), mload(add(transcript, 0x5860)))
            mstore(add(transcript, 0x5920), mload(add(transcript, 0x5880)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x58c0),
                        0x80,
                        add(transcript, 0x58c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5940), mload(add(transcript, 0x520)))
            mstore(add(transcript, 0x5960), mload(add(transcript, 0x540)))
            mstore(add(transcript, 0x5980), mload(add(transcript, 0x3720)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5940),
                        0x60,
                        add(transcript, 0x5940),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x59a0), mload(add(transcript, 0x58c0)))
            mstore(add(transcript, 0x59c0), mload(add(transcript, 0x58e0)))
            mstore(add(transcript, 0x59e0), mload(add(transcript, 0x5940)))
            mstore(add(transcript, 0x5a00), mload(add(transcript, 0x5960)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x59a0),
                        0x80,
                        add(transcript, 0x59a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5a20), mload(add(transcript, 0x400)))
            mstore(add(transcript, 0x5a40), mload(add(transcript, 0x420)))
            mstore(add(transcript, 0x5a60), mload(add(transcript, 0x3740)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5a20),
                        0x60,
                        add(transcript, 0x5a20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5a80), mload(add(transcript, 0x59a0)))
            mstore(add(transcript, 0x5aa0), mload(add(transcript, 0x59c0)))
            mstore(add(transcript, 0x5ac0), mload(add(transcript, 0x5a20)))
            mstore(add(transcript, 0x5ae0), mload(add(transcript, 0x5a40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5a80),
                        0x80,
                        add(transcript, 0x5a80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5b00), mload(add(transcript, 0xb80)))
            mstore(add(transcript, 0x5b20), mload(add(transcript, 0xba0)))
            mstore(add(transcript, 0x5b40), mload(add(transcript, 0x41a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5b00),
                        0x60,
                        add(transcript, 0x5b00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5b60), mload(add(transcript, 0x5a80)))
            mstore(add(transcript, 0x5b80), mload(add(transcript, 0x5aa0)))
            mstore(add(transcript, 0x5ba0), mload(add(transcript, 0x5b00)))
            mstore(add(transcript, 0x5bc0), mload(add(transcript, 0x5b20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5b60),
                        0x80,
                        add(transcript, 0x5b60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5be0), mload(add(transcript, 0xbc0)))
            mstore(add(transcript, 0x5c00), mload(add(transcript, 0xbe0)))
            mstore(add(transcript, 0x5c20), mload(add(transcript, 0x41e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5be0),
                        0x60,
                        add(transcript, 0x5be0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5c40), mload(add(transcript, 0x5b60)))
            mstore(add(transcript, 0x5c60), mload(add(transcript, 0x5b80)))
            mstore(add(transcript, 0x5c80), mload(add(transcript, 0x5be0)))
            mstore(add(transcript, 0x5ca0), mload(add(transcript, 0x5c00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5c40),
                        0x80,
                        add(transcript, 0x5c40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5cc0), mload(add(transcript, 0xc00)))
            mstore(add(transcript, 0x5ce0), mload(add(transcript, 0xc20)))
            mstore(add(transcript, 0x5d00), mload(add(transcript, 0x4220)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5cc0),
                        0x60,
                        add(transcript, 0x5cc0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5d20), mload(add(transcript, 0x5c40)))
            mstore(add(transcript, 0x5d40), mload(add(transcript, 0x5c60)))
            mstore(add(transcript, 0x5d60), mload(add(transcript, 0x5cc0)))
            mstore(add(transcript, 0x5d80), mload(add(transcript, 0x5ce0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5d20),
                        0x80,
                        add(transcript, 0x5d20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5da0), mload(add(transcript, 0xc40)))
            mstore(add(transcript, 0x5dc0), mload(add(transcript, 0xc60)))
            mstore(add(transcript, 0x5de0), mload(add(transcript, 0x4260)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5da0),
                        0x60,
                        add(transcript, 0x5da0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5e00), mload(add(transcript, 0x5d20)))
            mstore(add(transcript, 0x5e20), mload(add(transcript, 0x5d40)))
            mstore(add(transcript, 0x5e40), mload(add(transcript, 0x5da0)))
            mstore(add(transcript, 0x5e60), mload(add(transcript, 0x5dc0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5e00),
                        0x80,
                        add(transcript, 0x5e00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5e80), mload(add(transcript, 0xc80)))
            mstore(add(transcript, 0x5ea0), mload(add(transcript, 0xca0)))
            mstore(add(transcript, 0x5ec0), mload(add(transcript, 0x42a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5e80),
                        0x60,
                        add(transcript, 0x5e80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5ee0), mload(add(transcript, 0x5e00)))
            mstore(add(transcript, 0x5f00), mload(add(transcript, 0x5e20)))
            mstore(add(transcript, 0x5f20), mload(add(transcript, 0x5e80)))
            mstore(add(transcript, 0x5f40), mload(add(transcript, 0x5ea0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5ee0),
                        0x80,
                        add(transcript, 0x5ee0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5f60), mload(add(transcript, 0xcc0)))
            mstore(add(transcript, 0x5f80), mload(add(transcript, 0xce0)))
            mstore(add(transcript, 0x5fa0), mload(add(transcript, 0x42e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5f60),
                        0x60,
                        add(transcript, 0x5f60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5fc0), mload(add(transcript, 0x5ee0)))
            mstore(add(transcript, 0x5fe0), mload(add(transcript, 0x5f00)))
            mstore(add(transcript, 0x6000), mload(add(transcript, 0x5f60)))
            mstore(add(transcript, 0x6020), mload(add(transcript, 0x5f80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5fc0),
                        0x80,
                        add(transcript, 0x5fc0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6040), mload(add(transcript, 0xbc0)))
            mstore(add(transcript, 0x6060), mload(add(transcript, 0xbe0)))
            mstore(add(transcript, 0x6080), mload(add(transcript, 0x3960)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6040),
                        0x60,
                        add(transcript, 0x6040),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x60a0), mload(add(transcript, 0xb80)))
            mstore(add(transcript, 0x60c0), mload(add(transcript, 0xba0)))
            mstore(add(transcript, 0x60e0), mload(add(transcript, 0x6040)))
            mstore(add(transcript, 0x6100), mload(add(transcript, 0x6060)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x60a0),
                        0x80,
                        add(transcript, 0x60a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6120), mload(add(transcript, 0xc00)))
            mstore(add(transcript, 0x6140), mload(add(transcript, 0xc20)))
            mstore(add(transcript, 0x6160), mload(add(transcript, 0x3c80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6120),
                        0x60,
                        add(transcript, 0x6120),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6180), mload(add(transcript, 0x60a0)))
            mstore(add(transcript, 0x61a0), mload(add(transcript, 0x60c0)))
            mstore(add(transcript, 0x61c0), mload(add(transcript, 0x6120)))
            mstore(add(transcript, 0x61e0), mload(add(transcript, 0x6140)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6180),
                        0x80,
                        add(transcript, 0x6180),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6200), mload(add(transcript, 0xc40)))
            mstore(add(transcript, 0x6220), mload(add(transcript, 0xc60)))
            mstore(add(transcript, 0x6240), mload(add(transcript, 0x3ea0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x6200),
                        0x60,
                        add(transcript, 0x6200),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6260), mload(add(transcript, 0x6180)))
            mstore(add(transcript, 0x6280), mload(add(transcript, 0x61a0)))
            mstore(add(transcript, 0x62a0), mload(add(transcript, 0x6200)))
            mstore(add(transcript, 0x62c0), mload(add(transcript, 0x6220)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6260),
                        0x80,
                        add(transcript, 0x6260),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x62e0), mload(add(transcript, 0xc80)))
            mstore(add(transcript, 0x6300), mload(add(transcript, 0xca0)))
            mstore(add(transcript, 0x6320), mload(add(transcript, 0x4040)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x62e0),
                        0x60,
                        add(transcript, 0x62e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6340), mload(add(transcript, 0x6260)))
            mstore(add(transcript, 0x6360), mload(add(transcript, 0x6280)))
            mstore(add(transcript, 0x6380), mload(add(transcript, 0x62e0)))
            mstore(add(transcript, 0x63a0), mload(add(transcript, 0x6300)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6340),
                        0x80,
                        add(transcript, 0x6340),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x63c0), mload(add(transcript, 0xcc0)))
            mstore(add(transcript, 0x63e0), mload(add(transcript, 0xce0)))
            mstore(add(transcript, 0x6400), mload(add(transcript, 0x4120)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x63c0),
                        0x60,
                        add(transcript, 0x63c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x6420), mload(add(transcript, 0x6340)))
            mstore(add(transcript, 0x6440), mload(add(transcript, 0x6360)))
            mstore(add(transcript, 0x6460), mload(add(transcript, 0x63c0)))
            mstore(add(transcript, 0x6480), mload(add(transcript, 0x63e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x6420),
                        0x80,
                        add(transcript, 0x6420),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x64a0), mload(add(transcript, 0x5fc0)))
            mstore(add(transcript, 0x64c0), mload(add(transcript, 0x5fe0)))
            mstore(
                add(transcript, 0x64e0),
                0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
            )
            mstore(
                add(transcript, 0x6500),
                0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
            )
            mstore(
                add(transcript, 0x6520),
                0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
            )
            mstore(
                add(transcript, 0x6540),
                0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
            )
            mstore(add(transcript, 0x6560), mload(add(transcript, 0x6420)))
            mstore(add(transcript, 0x6580), mload(add(transcript, 0x6440)))
            mstore(
                add(transcript, 0x65a0),
                0x0181624e80f3d6ae28df7e01eaeab1c0e919877a3b8a6b7fbc69a6817d596ea2
            )
            mstore(
                add(transcript, 0x65c0),
                0x1783d30dcb12d259bb89098addf6280fa4b653be7a152542a28f7b926e27e648
            )
            mstore(
                add(transcript, 0x65e0),
                0x00ae44489d41a0d179e2dfdc03bddd883b7109f8b6ae316a59e815c1a6b35304
            )
            mstore(
                add(transcript, 0x6600),
                0x0b2147ab62a386bd63e6de1522109b8c9588ab466f5aadfde8c41ca3749423ee
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x8,
                        add(transcript, 0x64a0),
                        0x180,
                        add(transcript, 0x64a0),
                        0x20
                    ),
                    1
                ),
                success
            )
            success := and(eq(mload(add(transcript, 0x64a0)), 1), success)
        }
        return success;
    }

    function setPublicKey(bytes calldata _publicKey) external {
        _requireFromEntryPoint();
        publicKey = _publicKey;
    }

    function setInactiveTimeLimit(uint256 _InactiveTimeLimit) external {
        _requireFromEntryPoint();
        InactiveTimeLimit = _InactiveTimeLimit;
    }

    function setInheritor(address _inheritor) external {
        _requireFromEntryPoint();
        inheritor = _inheritor;
    }

    function inherit() external {
        require(inheritor == msg.sender, "not inheritor");
        require(
            block.timestamp - lastActiveTime > InactiveTimeLimit,
            "not inactive"
        );
        payable(inheritor).transfer(address(this).balance);
    }

    /// @inheritdoc BaseAccount
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        // TODO: public inputs with useropHash
        // if (!_verifyP256Proof(new uint256[](0), userOp.signature)) {
        //     return SIG_VALIDATION_FAILED;
        // }
        return 0;
    }
}
