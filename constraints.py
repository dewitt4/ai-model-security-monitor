monitor = AISecurityMonitor(
    model_name="my_model",
    input_constraints={
        'max_value': 1.0,
        'min_value': -1.0,
        'max_gradient': 50,
        'min_sparsity': 0.05
    }
)
