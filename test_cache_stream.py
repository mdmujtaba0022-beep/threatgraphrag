import urllib.request
import json
import time

def test_api():
    print("=== Testing FastAPI Endpoints ===")
    
    # 1. Stats initial
    req = urllib.request.Request("http://127.0.0.1:8000/api/cache/stats")
    stats = json.loads(urllib.request.urlopen(req).read().decode("utf-8"))
    print(f"[Initial Stats] Hits: {stats['hits']}, Misses: {stats['misses']}, Entries: {stats['total_entries']}")

    # 2. First Query (Cache Miss / Populates Cache)
    payload = json.dumps({"query": "APT29"}).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/threat-query",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    t0 = time.time()
    res1 = json.loads(urllib.request.urlopen(req).read().decode("utf-8"))
    elapsed1 = round(time.time() - t0, 3)
    print(f"[Query 1] Cache Hit: {res1.get('cache_hit')} | Traversal Time: {res1.get('traversal_time_seconds')}s | Total Time: {elapsed1}s")

    # 3. Second Query (Cache Hit)
    t0 = time.time()
    res2 = json.loads(urllib.request.urlopen(req).read().decode("utf-8"))
    elapsed2 = round(time.time() - t0, 3)
    print(f"[Query 2] Cache Hit: {res2.get('cache_hit')} | Traversal Time: {res2.get('traversal_time_seconds')}s | Total Time: {elapsed2}s")

    # 4. Stream Query SSE Test
    print("\n=== Testing SSE Token Streaming ===")
    stream_payload = json.dumps({"query": "APT29"}).encode("utf-8")
    req_stream = urllib.request.Request(
        "http://127.0.0.1:8000/api/threat-query-stream",
        data=stream_payload,
        headers={"Content-Type": "application/json"}
    )
    t_stream_start = time.time()
    first_chunk_time = None
    chunks_received = 0
    with urllib.request.urlopen(req_stream) as response:
        for line in response:
            line = line.decode("utf-8").strip()
            if line.startswith("data: "):
                if first_chunk_time is None:
                    first_chunk_time = round(time.time() - t_stream_start, 3)
                chunks_received += 1
                if chunks_received <= 3 or line == "data: [DONE]":
                    print(f"  Chunk received: {line[:60]}...")
    
    print(f"[Streaming Results] Time to First Token: {first_chunk_time}s | Total Chunks: {chunks_received}")

    # 5. Final Stats
    req = urllib.request.Request("http://127.0.0.1:8000/api/cache/stats")
    final_stats = json.loads(urllib.request.urlopen(req).read().decode("utf-8"))
    print("\n[Final Cache Stats]")
    print(f"  Total Entries: {final_stats['total_entries']}")
    print(f"  Hits: {final_stats['hits']}")
    print(f"  Misses: {final_stats['misses']}")
    print(f"  Hit Ratio: {final_stats['hit_ratio_percent']}%")
    print(f"  Estimated Tokens Saved: {final_stats['estimated_tokens_saved']}")
    print(f"  Latency Saved: {final_stats['estimated_latency_saved_seconds']}s")

if __name__ == "__main__":
    test_api()
