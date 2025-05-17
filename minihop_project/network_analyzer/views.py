from typing import Any

from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render

from .forms import PcapUploadForm
from .pcap_parser import parse_pcap


# Create your views here.
def upload_pcap(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = PcapUploadForm(request.POST, request.FILES)
        if form.is_valid():
            pcap_file = request.FILES["pcap_file"]
            try:
                analysis_results = parse_pcap(pcap_file)
                request.session["results"] = analysis_results
                return redirect("results")
            except Exception as e:
                return render(
                    request,
                    "upload.html",
                    {"form": form, "error": f"Error processing pcap file: {str(e)}"},
                )
    else:
        form = PcapUploadForm()
    return render(request, "upload.html", {"form": form})


def results(request: HttpRequest) -> HttpResponse:
    results: dict[str, Any] | None = request.session.get("results")
    if not results:
        return redirect("upload_pcap")
    return render(request, "results.html", {"results": results})
