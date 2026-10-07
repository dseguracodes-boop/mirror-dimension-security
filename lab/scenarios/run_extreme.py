import asyncio
import json
from lab.scenarios.extreme_stress_test import ExtremeStressTester


async def main():
    print("=" * 65)
    print("🔬 PRUEBA EXTREMA: RENDIMIENTO, INTEGRIDAD Y FUGA DE SECRETOS")
    print("=" * 65)

    tester = ExtremeStressTester()

    # Test 1: Concurrency & Race Conditions (1,000 parallel events)
    print("\n[1/4] CONCURRENCIA MASIVA (1.000 eventos asíncronos paralelos)...")
    res1 = await tester.benchmark_massive_concurrency(1000)
    print(json.dumps(res1, indent=2))

    # Test 2: Tamper Detection (Flipping 1 byte on disk)
    print("\n[2/4] INTEGRIDAD CRIPTOGRÁFICA (Alteración de 1 byte en disco)...")
    res2 = tester.test_evidence_tamper_detection()
    print(json.dumps(res2, indent=2))

    # Test 3: Real MITRE ATT&CK Extraction (50 real techniques from repo)
    print("\n[3/4] MITRE ATT&CK REAL (Extracción de 50 técnicas del repositorio)...")
    res3 = await tester.stress_real_mitre_techniques(50)
    print(json.dumps(res3, indent=2))

    # Test 4: Mirror Sanitizer Secret Leakage
    print("\n[4/4] FUGA DE SECRETOS EN LA DIMENSIÓN ESPEJO (11 variables)...")
    res4 = tester.test_sanitizer_secret_leakage()
    print(json.dumps(res4, indent=2))

    print("\n" + "=" * 65)
    print("🏁 FINALIZACIÓN DE PRUEBAS EXTREMAS")
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(main())
