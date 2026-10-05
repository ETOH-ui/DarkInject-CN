"""请求统计"""


def print_stats(req):
    st = req.stats()
    print("=" * 40)
    print(f"  请求总数: {st['total']}")
    print(f"  错误数:   {st['errors']}")
    print(f"  总耗时:   {st['time']:.2f}s")
    if st["total"]:
        print(f"  平均耗时: {st['time'] / st['total']:.3f}s")
    print("=" * 40)