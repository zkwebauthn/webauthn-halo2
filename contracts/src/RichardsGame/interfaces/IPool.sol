interface Pool {
    function depositAll(
        address[] calldata erc20,
        uint256[] calldata amounts,
        address[] calldata erc721,
        uint256[] calldata tokendIds
    ) external payable;

    function spin() external;

    function withdrawAll(
        address[] calldata erc20,
        uint256[] calldata amounts,
        address[] calldata erc721,
        uint256[] calldata tokendIds
    ) external payable;
}
