start "SIGNER_1" python signer.py --party_id 1 --port 5001 --num_parties 3 --threshold 2 --party_addresses 1:localhost:5001 2:localhost:5002 3:localhost:5003
start "SIGNER_2" python signer.py --party_id 2 --port 5002 --num_parties 3 --threshold 2 --party_addresses 1:localhost:5001 2:localhost:5002 3:localhost:5003
start "SIGNER_3" python signer.py --party_id 3 --port 5003 --num_parties 3 --threshold 2 --party_addresses 1:localhost:5001 2:localhost:5002 3:localhost:5003

python coordinator.py
