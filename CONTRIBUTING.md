# CONTRIBUTING

Thank you for considering contributing to our project! This document provides guidelines for contributing and the project's coding standards. Following these will make your contribution easier to incorporate and maintain the consistency and quality of the codebase.

## Code of Conduct

We expect all contributors to respect each other and communicate in a constructive manner. Please remember to treat everyone with respect, regardless of their level of experience, gender, gender identity and expression, sexual orientation, disability, personal appearance, body size, race, ethnicity, age, religion, or nationality. Any inappropriate behavior or harassment will not be tolerated.

## Project Directives

### File Structure

Our project follows a certain structure for better organization. The top-level directory consists of a `src` folder where all the source code is located, a `tests` folder for unit tests, and a `doc` folder for documentation. In the `src` directory, each hash function is placed in its own subdirectory, encapsulating its logic and keeping the codebase clean.

### Types Visibility

In general, types should be private unless they need to be exposed for a specific reason. Only types that are part of the public API, or are required for the implementation of public API methods, should be public. This approach encourages encapsulation and reduces the chance of unintended usage or dependencies.

### Building Block Types

Whenever possible, we encourage the use of internal building block types. These types have been developed with the specific requirements of the project in mind, and using them will ensure consistency across the project and will make the code easier to maintain.

### `std` Imports

This project is primarily `no_std`, so standard library imports should be avoided in the main codebase. However, `std` imports may be acceptable in the `tests` directory, where test code runs on platforms with a standard library available.

## External Crates

Before considering including an external crate, you should evaluate whether the functionality provided by the crate cannot be efficiently implemented within the project. In addition, the following considerations should be taken into account:

- The external crate must be maintained and have recent updates.
- The crate should be widely used and have a good reputation in the Rust community.
- The crate should not include `std` in its dependency chain.
- The crate should be compatible with the GPL-2.0-only license.

If you still believe that including an external crate is the right choice, please explain your reasoning in your pull request.

## Conclusion

Thank you for reading these guidelines and considering contributing to our project. We look forward to reviewing your pull requests!