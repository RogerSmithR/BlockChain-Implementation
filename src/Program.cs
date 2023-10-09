using System.Security.Cryptography;
using System.Text;

// function to create eliptic curve key pair
public class PairOfKeys
{
    public string PublicKey { get; set; }
    public string PrivateKey { get; set; }
    public PairOfKeys()
    {
        using (var ecdsa = ECDsa.Create(ECCurve.NamedCurves.brainpoolP256r1))
        {
            PublicKey = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
            PrivateKey = Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey());
        }
    }
}
public class User
{
    private string Name { get; set; }
    private List<PairOfKeys> ListOfKeys { get; set; }
    public User(string name)
    {
        Name = name;
        ListOfKeys = new List<PairOfKeys>();
    }
    public string GetPublicKey()
    {
        var newPairOfKey = new PairOfKeys();
        ListOfKeys.Add(newPairOfKey);
        return newPairOfKey.PublicKey;
    }
    public Transaction SendMoney(string ReceiverPublicKey, double amount)
    {
        var newPairOfKey = new PairOfKeys();
        ListOfKeys.Add(newPairOfKey);
        Transaction transaction = new Transaction(ReceiverPublicKey, newPairOfKey.PublicKey, amount, newPairOfKey.PrivateKey);
        return transaction;
    }
    public double GetBalance(Blockchain blockchain)
    {
        double balance = 0;
        if (ListOfKeys.Count == 0)
        {
            return balance;
        }
        foreach (var block in blockchain.Chain)
        {
            foreach (var transaction in block.MerkleRoot)
            {
                // search for the public key in the list of keys
                if (ListOfKeys.Any(x => x.PublicKey == transaction.OwnerPublicKey))
                {
                    balance -= transaction.Amount;
                }
                if (ListOfKeys.Any(x => x.PublicKey == transaction.ReceiverPublicKey))
                {
                    balance += transaction.Amount;
                }
            }
        }
        return balance;
    }
    public void PrintTransactions(Blockchain blockchain)
    {
        if (ListOfKeys.Count == 0)
        {
            return;
        }
        foreach (var block in blockchain.Chain)
        {
            foreach (var transaction in block.MerkleRoot)
            {
                // search for the public key in the list of keys
                if (ListOfKeys.Any(x => x.PublicKey == transaction.OwnerPublicKey))
                {
                    Console.WriteLine("  Send: -" + transaction.Amount);
                }
                if (ListOfKeys.Any(x => x.PublicKey == transaction.ReceiverPublicKey))
                {
                    Console.WriteLine("  Recv: +" + transaction.Amount);
                }
            }
        }
        Console.WriteLine("--------------------");
    }
}

public class Transaction
{
    public double Amount { get; private set; }
    public string ReceiverPublicKey { get; private set; }
    public string OwnerPublicKey { get; private set; }
    public string HashTransaction { get; private set; }
    public string OwnerSignature { get; private set; }

    public Transaction(string recvPublicKey, string senderPublicKey, double amount, string senderPrivateKey)
    {
        ReceiverPublicKey = recvPublicKey;
        OwnerPublicKey = senderPublicKey;
        HashTransaction = CalculateHashTransaction(); // hash of amount + receiver public key 
        OwnerSignature = SignTransaction(senderPrivateKey); // signature of hash transaction
        Amount = amount;
    }
    public string CalculateHashTransaction()
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes($"{Amount}-{ReceiverPublicKey}");
            byte[] hashBytes = sha256.ComputeHash(inputBytes);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }
    }
    public string SignTransaction(string privateKey)
    {
        // sign the hash of the transaction using ECDsa
        using (var ecdsa = ECDsa.Create(ECCurve.NamedCurves.brainpoolP256r1))
        {
            ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);
            return Convert.ToBase64String(ecdsa.SignData(Encoding.UTF8.GetBytes(HashTransaction), HashAlgorithmName.SHA256));
        }
    }
    public bool ValidateSignature()
    {
        // validate the signature of the transaction using ECDsa
        using (var ecdsa = ECDsa.Create(ECCurve.NamedCurves.brainpoolP256r1))
        {
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(OwnerPublicKey), out _);
            return ecdsa.VerifyData(Encoding.UTF8.GetBytes(HashTransaction), Convert.FromBase64String(OwnerSignature), HashAlgorithmName.SHA256);
        }
    }
}

public class MerkleTree
{
    public List<Transaction> Transactions { get; set; }
    public List<string> MerkleRoot { get; set; }
    public MerkleTree(List<Transaction> transactions)
    {
        Transactions = transactions;
        MerkleRoot = new List<string>();
        Build();
    }
    public void Build()
    {
        List<string> prevTreeLayer = new List<string>();
        foreach (var transaction in Transactions)
        {
            prevTreeLayer.Add(transaction.HashTransaction);
        }
        List<string> treeLayer = prevTreeLayer;
        while (treeLayer.Count != 1)
        {
            treeLayer = new List<string>();
            for (int i = 1; i < prevTreeLayer.Count; i++)
            {
                treeLayer.Add(CalculateHash(prevTreeLayer[i - 1], prevTreeLayer[i]));
            }
            prevTreeLayer = treeLayer;
        }
        MerkleRoot.Add(treeLayer[0]);
    }
    public string CalculateHash(string left, string right)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes($"{left}-{right}");
            byte[] hashBytes = sha256.ComputeHash(inputBytes);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }
    }
}

public class Block
{
    public int BlockNumber { get; set; }
    public DateTime TimeStamp { get; set; }
    public string PreviousHash { get; set; }
    public List<Transaction> MerkleRoot { get; set; }
    public string Hash { get; set; }
    public int Nonce { get; set; }
    public Block(DateTime timeStamp, string previousHash, List<Transaction> merkleRoot)
    {
        TimeStamp = timeStamp;
        PreviousHash = previousHash;
        MerkleRoot = merkleRoot;
        Hash = CalculateHash();
        Nonce = 0;
    }
    public string CalculateHash()
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes($"{TimeStamp}-{PreviousHash ?? ""}-{MerkleRoot}-{Nonce}");
            byte[] outputBytes = sha256.ComputeHash(inputBytes);
            return BitConverter.ToString(outputBytes).Replace("-", "").ToLower();
        }
    }
    public void Mine(int difficulty)
    {
        string hashValidationTemplate = new string('0', difficulty);
        while (Hash.Substring(0, difficulty) != hashValidationTemplate)
        {
            Nonce++;
            Hash = CalculateHash();
        }
        //Console.WriteLine($"Block mined: {Hash}");
    }
}
public class Blockchain
{
    public List<Block> Chain { get; set; }
    public int Difficulty { get; set; }
    public Blockchain()
    {
        Chain = new List<Block>();
        Difficulty = 2;
    }
    public void AddBlock(Block block)
    {
        if (Chain.Count == 0)
        {
            block.PreviousHash = string.Empty;
        }
        else
        {
            block.PreviousHash = Chain[Chain.Count - 1].Hash;
        }
        block.Mine(Difficulty);
        block.BlockNumber = Chain.Count;
        Chain.Add(block);
    }
    public void PrintChain()
    {
        foreach (var block in Chain)
        {
            Console.WriteLine("--------------------------------------------------");
            Console.WriteLine($"Block #{block.BlockNumber} [{block.TimeStamp}]");
            Console.WriteLine($"  Hash: {block.Hash}");
            Console.WriteLine($"  Previous Hash: {block.PreviousHash}");
            Console.WriteLine($"  Nonce: {block.Nonce}");
            Console.WriteLine($"  Merkle Root: {string.Join(",", block.MerkleRoot.Select(x => x.HashTransaction))}");
            Console.WriteLine();
            foreach (var transaction in block.MerkleRoot)
            {
                Console.WriteLine("     -------------------");
                Console.WriteLine($"    Transaction: {transaction.HashTransaction}");
                Console.WriteLine($"      Owner: {transaction.OwnerPublicKey}");
                Console.WriteLine($"      Receiver: {transaction.ReceiverPublicKey}");
                Console.WriteLine($"      Amount: {transaction.Amount}");
                Console.WriteLine($"      Signature: {transaction.OwnerSignature}");
                Console.WriteLine($"      Signature Valid: {transaction.ValidateSignature()}");
                Console.WriteLine();
            }
        }
    }
}

class Program
{
    static void Main()
    {
        // 6 users and add 100.00 balance to Alice
        User initialUser = new User("InitialUser");
        User alice = new User("Alice");
        User bob = new User("Bob");
        User roger = new User("Roger");
        User charlie = new User("Charlie");
        User silvia = new User("Silvia");

        //----------------------- GENESIS BLOCK ------------------//
        // add the intial 100.00 balance to Alice
        Transaction genesisTransaction = initialUser.SendMoney(alice.GetPublicKey(), 100);
        MerkleTree genesisMerkleTree = new MerkleTree(new List<Transaction> { genesisTransaction });
        Block genesisBlock = new Block(DateTime.Now, string.Empty, genesisMerkleTree.Transactions);
        Blockchain blockchain = new Blockchain();
        blockchain.AddBlock(genesisBlock);

        //----------------------- BLOCK #1 -----------------------//
        Transaction transaction1 = alice.SendMoney(bob.GetPublicKey(), 5.0);
        Transaction transaction2 = bob.SendMoney(roger.GetPublicKey(), 5.0);
        Transaction transaction3 = roger.SendMoney(charlie.GetPublicKey(), 5.0);
        Transaction transaction4 = charlie.SendMoney(silvia.GetPublicKey(), 5.0);
        MerkleTree merkleTree = new MerkleTree(new List<Transaction> { transaction1, transaction2, transaction3, transaction4 });
        Block block1 = new Block(DateTime.Now, genesisBlock.Hash, merkleTree.Transactions);
        blockchain.AddBlock(block1);

        //----------------------- BLOCK #2 -----------------------//
        Transaction transaction5 = alice.SendMoney(bob.GetPublicKey(), 10.0);
        Transaction transaction6 = bob.SendMoney(roger.GetPublicKey(), 20.0);
        Transaction transaction7 = roger.SendMoney(charlie.GetPublicKey(), 30.0);
        Transaction transaction8 = charlie.SendMoney(silvia.GetPublicKey(), 40.0);
        MerkleTree merkleTree2 = new MerkleTree(new List<Transaction> { transaction5, transaction6, transaction7, transaction8 });
        Block block2 = new Block(DateTime.Now, block1.Hash, merkleTree2.Transactions);
        blockchain.AddBlock(block2);

        //----------------------- BLOCK #3 -----------------------//
        Transaction transaction9 = alice.SendMoney(bob.GetPublicKey(), 50.0);
        Transaction transaction10 = bob.SendMoney(roger.GetPublicKey(), 60.0);
        Transaction transaction11 = bob.SendMoney(roger.GetPublicKey(), 60.0);
        Transaction transaction12 = roger.SendMoney(charlie.GetPublicKey(), 70.0);
        MerkleTree merkleTree3 = new MerkleTree(new List<Transaction> { transaction9, transaction10, transaction11, transaction12 });
        Block block3 = new Block(DateTime.Now, block2.Hash, merkleTree3.Transactions);
        blockchain.AddBlock(block3);

        blockchain.PrintChain();

        // print balance of all users
        Console.WriteLine($"Alice balance: {alice.GetBalance(blockchain)}");
        alice.PrintTransactions(blockchain);
        Console.WriteLine($"Bob balance: {bob.GetBalance(blockchain)}");
        bob.PrintTransactions(blockchain);
        Console.WriteLine($"Roger balance: {roger.GetBalance(blockchain)}");
        roger.PrintTransactions(blockchain);
        Console.WriteLine($"Charlie balance: {charlie.GetBalance(blockchain)}");
        charlie.PrintTransactions(blockchain);
        Console.WriteLine($"Silvia balance: {silvia.GetBalance(blockchain)}");
        silvia.PrintTransactions(blockchain);


        Console.ReadLine();
    }
}