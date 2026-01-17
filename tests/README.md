# BittrRt Tests

This folder contains test suites for the BittrRt application.

## Test Files

### test_config.py

Tests for configuration file creation and command line argument handling.

#### TestConfigCreation

Tests related to creating and managing the config file:

- `test_create_config_default_values`: Verifies config file creation with default values
- `test_create_config_with_custom_values`: Tests config creation with custom CLI arguments
- `test_create_config_unknown_argument_warning`: Ensures unknown arguments trigger warnings
- `test_create_config_overwrite_with_changes`: Tests overwriting existing config with user confirmation
- `test_create_config_overwrite_abort`: Verifies aborting config overwrite works correctly
- `test_create_config_no_changes_warning`: Checks warning when no changes are detected

#### TestCommandLineArguments

Tests for command line argument parsing and handling:

- `test_cli_overrides_config_file`: Ensures CLI arguments override config file values
- `test_sync_test_flag`: Verifies the `--sync-test` flag is properly recognized
- `test_no_config_file_warning`: Tests warning message when config file is missing
- `test_multiple_cli_arguments`: Tests handling multiple CLI arguments simultaneously

## Running Tests

Run all tests in this folder:

```bash
python -m unittest discover tests
```

Run a specific test file:

```bash
python -m unittest tests.test_config
```

Run a specific test case:

```bash
python -m unittest tests.test_config.TestConfigCreation.test_create_config_default_values
```

Run tests with verbose output:

```bash
python -m unittest tests.test_config -v
```

## Test Coverage

The tests cover:
- Config file creation with default and custom values
- Config file overwriting with user confirmation
- Unknown argument detection
- CLI argument parsing and priority over config file values
- Flag-based arguments (like `--sync-test`)
- Error handling and user warnings
