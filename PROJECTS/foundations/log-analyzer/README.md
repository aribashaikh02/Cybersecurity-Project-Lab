# Sample Log Analyzer

Counts common log levels in a text file. Use the included synthetic sample log or another log you are authorized to inspect. The script does not send data anywhere.

## Run

```bash
python log_analyzer.py sample.log
```

The output shows counts for `INFO`, `WARNING`, `ERROR`, and `DEBUG` lines. This is a simple learning example, not a full SIEM or incident detector.
