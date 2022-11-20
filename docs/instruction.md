# PyDay BCN 2022 Workshop "Friendly fuzzing for your Python SaaS applications" step-by-step instruction

## Prerequisites
For the following workshop be sure, that
1. You have access to internet :-)
1. *Docker* and *Docker Compose* are installed on your laptop
1. Prebuild all needed docker images
    1. Go to director `fuzz-simple-example` and run build command for `fuzz` service
        ```
        cd fuzz-simple-example && docker-compose build fuzz
        ```
    1. Go to directory of the second example and run build command for `fuzz` service
        ```
        cd ../fuzz-drf-example && docker-compose build fuzz
        ```

## Let's fuzz simple example!

Let's start with the simple example of the fuzzing using *Atheris* library. Open the source code and go to the folder `fuzz-simple-example`
```
cd fuzz-simple-example
```

Our fuzzing and fuzzed code are in the same file `fuzz.py`. Open it in your most loved editor and let's write the code for the fuzzer there

1. Before writing any code for the fuzzer you need to specify for *Atheris* what code it should track. Since *Atheris* use Code Coverage Feedback to track the quality and mutate the input data you should instrument the code, that you are going to fuzz. Here you have do functions `check_permission` and `do_calc`. The `do_calc` function is an interface function, that you are going to fuzz. Let's allow *Atheris* to instrument these functions. Put the `@atheris.instrument_func` decorator on them.

    ```
    @atheris.instrument_func
    def check_permission(permission: str) -> bool:
        if permission == 'fuzzing_is_available':
            return False
        ...

    @atheris.instrument_func
    def do_calc(permission):
        is_available = check_permission(permission)
        ...
    ```

1. Now let's write the code to run fuzzing. We have an empty function `run_fuzzing`. Here you'll write the fuzzer code. To allow *Atheris* to generate new input data and run `run_fuzzing` function you should setup and run *Atheris* fuzzing. Add this code to the bottom

    ```
    def run_fuzzing(data: bytes):
        pass

    atheris.Setup(sys.argv, run_fuzzing)
    atheris.Fuzz()
    ```

1. Let's run and check what do you have now
    ```
    > docker-compose build fuzz
    > docker-compose run --service-ports fuzz
    ```

    The output of the command:
    ```
    > docker-compose run --service-ports fuzz
    INFO: Using built-in libfuzzer
    WARNING: Failed to find function "__sanitizer_acquire_crash_state".
    WARNING: Failed to find function "__sanitizer_print_stack_trace".
    WARNING: Failed to find function "__sanitizer_set_death_callback".
    INFO: Running with entropic power schedule (0xFF, 100).
    INFO: Seed: 2065693616
    INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
    INFO: A corpus is not provided, starting from an empty corpus
    #2  INITED exec/s: 0 rss: 34Mb
    WARNING: no interesting inputs were found so far. Is the code instrumented for coverage?
    This may also happen if the target rejected all inputs we tried so far
    Done 100000 in 0 second(s)
    ```

    Well, you see that *Atheris* found nothing insteresting. And that's true - you don't run the instrumented functions! Let's do it!

1. To run the fuzzed functions with data you have to generate the samples of data. Yes, you have a mutated bytes as `data` parameter in `run_fuzzing` function. But it is just a bytes. And to make fuzzing effectivly you need generate something meaningful to your `do_calc` function. Function `do_calc` has a string as an input. So let's generate a sample strings from the input mutated bytes. To do it *Atheris* provides the special `FuzzedDataProvider` object. It has a lot of built-in methods to generate ints, strings, bools from the provided amount of bytes. Let's define it inside the `run_fuzzing` function
    ```
    def run_fuzzin(data: bytes):
        dp = atheris.FuzzedDataProvider(data)
        ...
    ```

1. Now let's generate the unicode string for the input of the `do_calc` function
    ```
     def run_fuzzin(data: bytes):
        dp = atheris.FuzzedDataProvider(data)
        permission = dp.ConsumeUnicodeNoSurrogates(???)
    ```

1. `ConsumeUnicodeNoSurrogates` has a string length as an input parameter. What length you should provide there? Good question... Well, let's also make it choosen by *Atheris*
    ```
    def run_fuzzin(data: bytes):
        dp = atheris.FuzzedDataProvider(data)

        permission_legth = dp.ConsumeIntInRange(0, 32)
        permission = dp.ConsumeUnicodeNoSurrogates(permission_legth)
    ```

    Number of bytes do not guarantee that the final unicode will contain the exact number. It guarantees that it will be no more than provided number

1. And final step - invoke the `do_calc` function
    ```
    def run_fuzzin(data: bytes):
        dp = atheris.FuzzedDataProvider(data)

        permission_legth = dp.ConsumeIntInRange(0, 32)
        permission = dp.ConsumeUnicodeNoSurrogates(permission_legth)

        do_calc(permission)
    ```

1. Let's run it again!
    ```
    > docker-compose build fuzz
    > docker-compose run --service-ports fuzz
    ```

    The output of the command
    ```
    > docker-compose run --service-ports fuzz
    INFO: Using built-in libfuzzer
    WARNING: Failed to find function "__sanitizer_acquire_crash_state".
    WARNING: Failed to find function "__sanitizer_print_stack_trace".
    WARNING: Failed to find function "__sanitizer_set_death_callback".
    INFO: Running with entropic power schedule (0xFF, 100).
    INFO: Seed: 258538736
    INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
    INFO: A corpus is not provided, starting from an empty corpus
    #2  INITED cov: 5 ft: 5 corp: 1/1b exec/s: 0 rss: 34Mb
    Done 100000 in 0 second(s)
    ```

1. Perfect! It works. But what are results of the fuzzing? Can it find some erros in the code? The answer is - yes! Let's emulate that you have an unhandled exception in your code. To do it - modify the `elif permission == 'check_permission':` branch in function `check_permission` to raise the exception
    ```
    @atheris.instrument_func
    def check_permission(permission: str) -> bool:
        ...
        elif permission == 'check_permission':
            raise RuntimeError('Fuzzing!!!')
        ...
    ```

1. And run it again
    ```
    > docker-compose build fuzz
    > docker-compose run --service-ports fuzz
    ```

    And it automatically found the unhandled exception in the code!
    ```
    > docker-compose run --service-ports fuzz
    INFO: Using built-in libfuzzer
    WARNING: Failed to find function "__sanitizer_acquire_crash_state".
    WARNING: Failed to find function "__sanitizer_print_stack_trace".
    WARNING: Failed to find function "__sanitizer_set_death_callback".
    INFO: Running with entropic power schedule (0xFF, 100).
    INFO: Seed: 3549309748
    INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
    INFO: A corpus is not provided, starting from an empty corpus
    #2  INITED cov: 5 ft: 5 corp: 1/1b exec/s: 0 rss: 34Mb

     === Uncaught Python exception: ===
    RuntimeError: Fuzzing!!!
    Traceback (most recent call last):
      File "/app/fuzz.py", line 33, in run_fuzzing
        do_calc(permission)
      File "/app/fuzz.py", line 21, in do_calc
        if is_available:
      File "/app/fuzz.py", line 14, in check_permission
        return True
    RuntimeError: Fuzzing!!!

    ==1== ERROR: libFuzzer: fuzz target exited
    SUMMARY: libFuzzer: fuzz target exited
    MS: 3 ChangeByte-CopyPart-CMP- DE: "check_permission"-; base unit: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
    0x3b,0x63,0x68,0x65,0x63,0x6b,0x5f,0x70,0x65,0x72,0x6d,0x69,0x73,0x73,0x69,0x6f,0x6e,0x3b,
    ;check_permission;
    artifact_prefix='./'; Test unit written to ./crash-33a93877f7e7f5296e97381eb36e5f59e6094003
    Base64: O2NoZWNrX3Blcm1pc3Npb247
    ```

1. Also you can track the coverage during the *Atheris* execution. Return back the code with exception in the `check_permission` function
    ```
    @atheris.instrument_func
    def check_permission(permission: str) -> bool:
        ...
        elif permission == 'check_permission':
            return True
        ...
    ```

1. Build and run the coverage service from Docker Compose and open the `http://0.0.0.0:8000` in your browser
    ```
    > docker-compose build coverage
    > docker-compose run --service-ports coverage
    INFO: Using built-in libfuzzer
    WARNING: Failed to find function "__sanitizer_acquire_crash_state".
    WARNING: Failed to find function "__sanitizer_print_stack_trace".
    WARNING: Failed to find function "__sanitizer_set_death_callback".
    INFO: Running with entropic power schedule (0xFF, 100).
    INFO: Seed: 3832004908
    INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
    INFO: A corpus is not provided, starting from an empty corpus
    #2  INITED cov: 5 ft: 5 corp: 1/1b exec/s: 0 rss: 45Mb
    #87557  NEW    cov: 6 ft: 6 corp: 2/27b lim: 868 exec/s: 0 rss: 45Mb L: 26/26 MS: 5 ChangeByte-CopyPart-ShuffleBytes-ShuffleBytes-CMP- DE: "fuzzing_is_not_available"-
    #121597 NEW    cov: 7 ft: 7 corp: 3/45b lim: 1200 exec/s: 0 rss: 45Mb L: 18/26 MS: 5 ChangeBit-CrossOver-CrossOver-CMP-CMP- DE: "\377\377"-"check_permission"-
    #157338 NEW    cov: 9 ft: 9 corp: 4/67b lim: 1550 exec/s: 0 rss: 45Mb L: 22/26 MS: 1 EraseBytes-
    #524288 pulse  cov: 9 ft: 9 corp: 4/67b lim: 4096 exec/s: 174762 rss: 45Mb
    #1048576    pulse  cov: 9 ft: 9 corp: 4/67b lim: 4096 exec/s: 174762 rss: 45Mb
    #2097152    pulse  cov: 9 ft: 9 corp: 4/67b lim: 4096 exec/s: 174762 rss: 45Mb
    #4194304    pulse  cov: 9 ft: 9 corp: 4/67b lim: 4096 exec/s: 174762 rss: 45Mb
    Done 5000000 in 29 second(s)
    Wrote HTML report to htmlcov/index.html
    Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
    ```

    And the overall coverage is 92%! Amazing!

    ![Coverage fuzzing results](./images/fuzz-simple-example-coverage.png)

1. Finally you know how to cook *Atheris* in a simple example! Let's move to more complex examples


## Let's fuzz the Django REST Framework!

TBA
