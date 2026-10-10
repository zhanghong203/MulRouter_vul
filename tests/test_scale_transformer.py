from adaptive_mulvul.scale_transformer import ScaleTransformer


def test_scale_transformer_serializes_c_control_flow_without_an_api_call():
    code = """int clamp(int x) {
    if (x < 0) return 0;
    return x;
}"""

    result = ScaleTransformer().transform(code)

    assert result.startswith("[SCALE language=c]")
    assert "parse_errors=0" in result
    assert "function_definition" in result
    assert "if_statement" in result
    assert "return_statement" in result
