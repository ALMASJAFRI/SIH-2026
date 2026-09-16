from backend.forensics import IPGeoLookupTool, generate_journey_map

tool = IPGeoLookupTool(api_token=None)

ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
m = generate_journey_map(ips, tool)

print("Map is None?", m is None)
if m is not None:
    html = m.get_root()._repr_html_()
    print("HTML length:", len(html))
    open("test_map.html", "w", encoding="utf-8").write(html)
    print("Open test_map.html in your browser.")