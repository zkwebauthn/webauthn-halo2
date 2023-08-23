interface IPriceOracle {
    function getERC20Price(
        address token,
        uint256 amount
    ) external view returns (uint256);

    function getEthPrice(uint256 amount) external view returns (uint256);

    function getERC721Price(
        address token,
        uint256 tokenId
    ) external view returns (uint256);
}
