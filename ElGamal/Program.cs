
ElGamal q = new ElGamal(20996023);
Console.WriteLine($"P: {q.P}\ng: {q.g}\nOpen: {q.KOpen}");

string message = "Hello world and elgamal";
Console.WriteLine("Input text: "+message);

List<decimal[]> text = q.Encrypting(message);


Console.WriteLine("Encrypted...");
for (int i = 0; i < text.Count; i++)
{
    Console.Write("{" + text[i][0] + ", " + text[i][1] + "}, ");
}

Console.WriteLine("Decrypted...");
Console.WriteLine(q.Decrypting(text, q.P, q.KClose));