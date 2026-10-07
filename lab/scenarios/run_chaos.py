import asyncio
import json
from lab.scenarios.chaos_break_tests import ChaosBreakTester


async def main():
    print("=" * 60)
    print("🥊 RUNNING DIMENSIÓN ESPEJO CHAOS & BREAK TESTING SUITE")
    print("=" * 60)

    tester = ChaosBreakTester()

    # Test 1: Concurrency Flood
    print("\n[1/4] Testing High-Concurrency Event Flood (200 parallel events)...")
    res1 = await tester.test_high_concurrency_flood(200)
    print(json.dumps(res1, indent=2))

    # Test 2: Adversarial Evasion (Low-and-Slow / Sub-threshold)
    print("\n[2/4] Testing Adversarial Evasion & Sub-threshold Bypasses...")
    res2 = await tester.test_adversarial_evasion()
    print(json.dumps(res2, indent=2))

    # Test 3: Fuzzing & Malformed Payloads
    print("\n[3/4] Testing Fuzzing Payloads (Null bytes, Unicode, 200KB strings)...")
    res3 = await tester.test_fuzzing_and_malformed_payloads()
    print(json.dumps(res3, indent=2))

    # Test 4: False Flag DoS / Self-Lockout
    print("\n[4/4] Testing False Flag Global Lockdown Attack...")
    res4 = await tester.test_false_flag_dos()
    print(json.dumps(res4, indent=2))

    print("\n" + "=" * 60)
    print("🥊 CHAOS SUITE FINISHED")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
