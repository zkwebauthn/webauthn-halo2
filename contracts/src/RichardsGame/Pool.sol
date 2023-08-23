/**
 * @notice This is a gambling pool, which lets you gamble with ERC20s and NFTs, similar to csgoempire.co
 * 1. Users deposit NFTs and ERC20s into the pool and receive a proportional amount of point
 * 2. Every hour, the pool is spun, a random number between 0 and the total amount of points is generated
 * 3. The user who has the point wins everything in the pool
 */
import "./interfaces/IPriceOracle.sol";
import "./interfaces/IRandomNumberGenerator.sol";
import "../callback/TokenCallbackHandler.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

contract Pool is TokenCallbackHandler {
    mapping(address => tickets) public deposits;
    struct tickets {
        uint256 startIndex;
        uint256 endIndex;
    }
    uint256 totalPrevDepositValue;
    uint256 depositValue;
    uint256 winningNumber;
    uint256 withdrawExpiration;

    IPriceOracle public oracle;
    IRandomNumberGenerator public random;
    uint256 WITHDRAW_TIME = 30 seconds;

    constructor(IPriceOracle _oracle, IRandomNumberGenerator _random) {
        oracle = _oracle;
        random = _random;
        emit NewOracle(address(_oracle));
        emit NewRandomNumberGenerator(address(_random));
    }

    function depositEth() internal returns (uint256 value) {
        value = oracle.getEthPrice(msg.value);
        emit DepositEth(msg.sender, msg.value, value);
    }

    function depositERC20(
        address token,
        uint256 amount
    ) internal returns (uint256 value) {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        value = oracle.getERC20Price(token, amount);
        emit DepositERC20(msg.sender, token, amount, value);
    }

    function depositERC721(
        address token,
        uint256 tokenId
    ) internal returns (uint256 value) {
        IERC721(token).transferFrom(msg.sender, address(this), tokenId);
        value = oracle.getERC721Price(token, tokenId);
        emit DepositERC721(msg.sender, token, tokenId, value);
    }

    function depositAll(
        address[] calldata erc20,
        uint256[] calldata amounts,
        address[] calldata erc721,
        uint256[] calldata tokendIds
    ) public payable {
        require(block.timestamp > withdrawExpiration, "Withdraw not expired");
        uint256 _depositValue;
        for (uint256 i = 0; i < erc20.length; i++) {
            _depositValue += depositERC20(erc20[i], amounts[i]);
        }
        for (uint256 i = 0; i < erc721.length; i++) {
            _depositValue += depositERC721(erc721[i], tokendIds[i]);
        }
        _depositValue += depositEth();
        deposits[msg.sender].startIndex = depositValue;
        deposits[msg.sender].endIndex = depositValue + _depositValue;
        depositValue += _depositValue;
        emit DepositAll(
            msg.sender,
            _depositValue,
            deposits[msg.sender].startIndex,
            deposits[msg.sender].endIndex
        );
    }

    function spin() public {
        winningNumber =
            (random.getRandomNumber() %
                (depositValue - totalPrevDepositValue)) +
            totalPrevDepositValue;
        totalPrevDepositValue = depositValue;
        withdrawExpiration = block.timestamp + WITHDRAW_TIME;
        emit Spin(winningNumber);
    }

    function withdraw(address winner) internal {
        payable(winner).call{value: msg.value}("");
        emit Withdraw(winner, msg.value);
    }

    function withdrawERC20(
        address winner,
        address token,
        uint256 amount
    ) internal {
        IERC20(token).transferFrom(address(this), winner, amount);
        emit WithdrawERC20(winner, token, amount);
    }

    function withdrawERC721(
        address winner,
        address token,
        uint256 tokenId
    ) internal {
        IERC721(token).transferFrom(address(this), winner, tokenId);
        emit WithdrawERC721(winner, token, tokenId);
    }

    function withdrawAll(
        address[] calldata erc20,
        uint256[] calldata amounts,
        address[] calldata erc721,
        uint256[] calldata tokendIds
    ) public {
        require(
            deposits[msg.sender].startIndex <= winningNumber &&
                deposits[msg.sender].endIndex >= winningNumber,
            "You didn't win"
        );
        require(block.timestamp < withdrawExpiration, "Withdraw expired");
        withdraw(msg.sender);
        for (uint256 i = 0; i < erc20.length; i++) {
            withdrawERC20(msg.sender, erc20[i], amounts[i]);
        }
        for (uint256 i = 0; i < erc721.length; i++) {
            withdrawERC721(msg.sender, erc721[i], tokendIds[i]);
        }
    }

    receive() external payable {}

    event NewOracle(address indexed oracle);
    event NewRandomNumberGenerator(address indexed random);
    event DepositEth(address indexed user, uint256 amount, uint256 value);
    event DepositERC20(
        address indexed user,
        address indexed token,
        uint256 amount,
        uint256 value
    );
    event DepositERC721(
        address indexed user,
        address indexed token,
        uint256 tokenId,
        uint256 value
    );
    event DepositAll(
        address indexed user,
        uint256 value,
        uint256 startIndex,
        uint256 endIndex
    );
    event Spin(uint256 winningNumber);
    event Withdraw(address indexed user, uint256 amount);
    event WithdrawERC20(
        address indexed user,
        address indexed token,
        uint256 amount
    );
    event WithdrawERC721(
        address indexed user,
        address indexed token,
        uint256 tokenId
    );
}
