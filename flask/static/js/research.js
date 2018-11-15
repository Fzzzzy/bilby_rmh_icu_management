$(document).ready(function() {
	$(".nav-link").click(function() {
		$("#icu-discharge-drugs-result").hide(200);
		$("#all-data-result").hide(200);
		$("#patient-drug-detail ul").hide(200);
	});

	$("#icu-discharge-drugs #icu-back-button").click(function() {
		$("#icu-discharge-drugs").hide(200);
		var len = $("#icu-discharge-drugs input").length;
		$("#research-main-panel").show(200);
		for (var i = 0; i < len; i++) {
			$("#icu-discharge-drugs input").val("");
		}
		$("#icu-discharge-drugs select").val("none");
	});

	$("#icu-discharge-drugs #icu-search-button").click(function() {
		//$("#icu-discharge-drugs").hide(200);
		$("#icu-discharge-drugs-result").show(200);
	});

	$("#icu-discharge-drugs-result #icu-result-back-button").click(function() {
		$("#icu-discharge-drugs-result").hide(200);
		//$("#icu-discharge-drugs").show(200);
	});

	$("#top-drug-list #top-search-button").click(function() {
		$("#top-drug-list ul").show(200);
	});

	$("#top-drug-list #top-back-button").click(function() {
		$("#top-drug-list").hide(200);
		$("#research-main-panel").show(200);
	});

	$("#patient-drug-detail #patient-search-button").click(function() {
		$("#patient-drug-detail ul").show(200);
		$("#patient-drug-detail #patient-export-button").show(200);
	});

	$("#patient-drug-detail #patient-back-button").click(function() {
		$("#patient-drug-detail ul").hide(200);
		$("#patient-drug-detail #patient-export-button").hide(200);
		//$("#patient-drug-detail").hide(200);
		var len = $("#patient-drug-detail input").length;
		//$("#research-main-panel").show(200);
		for (var i = 0; i < len; i++) {
			$("#patient-drug-detail input").val("");
		}
		$("#patient-drug-detail select").val("none");
	});

	$("#export-all-data #all-data-search-button").click(function() {
		$("#all-data-result").show(200);
	});

	$("#export-all-data #all-result-back-button").click(function() {
		$("#all-data-result").hide(200);
		//$("#research-main-panel").show(200);
	});

});





