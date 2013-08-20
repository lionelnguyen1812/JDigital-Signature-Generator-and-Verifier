/* @author chad */
package gui;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

public class MainFrame extends javax.swing.JFrame {

    JFileChooser fc = new JFileChooser("C:\\Users\\chad\\Desktop");

    public MainFrame() {
        initComponents();
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jButton4 = new javax.swing.JButton();
        pnlBody = new javax.swing.JPanel();
        tabPanel = new javax.swing.JTabbedPane();
        pnlGenTab = new javax.swing.JPanel();
        pnlGenTabHeader = new javax.swing.JPanel();
        lblGenTitle = new javax.swing.JLabel();
        pnlGenTabFooter = new javax.swing.JPanel();
        btnGenerate = new javax.swing.JButton();
        pnlGenTabBody = new javax.swing.JPanel();
        lblSelectHint = new javax.swing.JLabel();
        txtOrgFile = new javax.swing.JTextField();
        btnOrgChoose = new javax.swing.JButton();
        lblFileHint = new javax.swing.JLabel();
        pnlVerTab = new javax.swing.JPanel();
        pnlVerTabHeader = new javax.swing.JPanel();
        lblVerTitle = new javax.swing.JLabel();
        pnlVerTabFooter = new javax.swing.JPanel();
        btnVerify = new javax.swing.JButton();
        pnlVerTabBody = new javax.swing.JPanel();
        lblVerifyHine = new javax.swing.JLabel();
        lblFileHine = new javax.swing.JLabel();
        txtVerifyFile = new javax.swing.JTextField();
        btnVerChoose = new javax.swing.JButton();
        lblSignHint = new javax.swing.JLabel();
        txtSignFile = new javax.swing.JTextField();
        btnSignChoose = new javax.swing.JButton();
        lblPubHint = new javax.swing.JLabel();
        txtPubkeyFile = new javax.swing.JTextField();
        btnPubkeyChoose = new javax.swing.JButton();
        pnlFooter = new javax.swing.JPanel();
        pnlStt = new javax.swing.JPanel();
        lblStatus = new javax.swing.JLabel();
        btnExit = new javax.swing.JButton();

        jButton4.setText("Browse");

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        pnlBody.setLayout(new javax.swing.BoxLayout(pnlBody, javax.swing.BoxLayout.LINE_AXIS));

        pnlGenTab.setLayout(new java.awt.BorderLayout());

        lblGenTitle.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        lblGenTitle.setText("Digital Signature Generator");
        pnlGenTabHeader.add(lblGenTitle);

        pnlGenTab.add(pnlGenTabHeader, java.awt.BorderLayout.PAGE_START);

        btnGenerate.setText("Generate Signature");
        btnGenerate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnGenerateActionPerformed(evt);
            }
        });
        pnlGenTabFooter.add(btnGenerate);

        pnlGenTab.add(pnlGenTabFooter, java.awt.BorderLayout.PAGE_END);

        lblSelectHint.setText("Select the file for which a Signature is to be generated");

        btnOrgChoose.setText("Browse");
        btnOrgChoose.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnOrgChooseActionPerformed(evt);
            }
        });

        lblFileHint.setText("File:");

        javax.swing.GroupLayout pnlGenTabBodyLayout = new javax.swing.GroupLayout(pnlGenTabBody);
        pnlGenTabBody.setLayout(pnlGenTabBodyLayout);
        pnlGenTabBodyLayout.setHorizontalGroup(
            pnlGenTabBodyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlGenTabBodyLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlGenTabBodyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(pnlGenTabBodyLayout.createSequentialGroup()
                        .addComponent(lblSelectHint)
                        .addGap(0, 114, Short.MAX_VALUE))
                    .addGroup(pnlGenTabBodyLayout.createSequentialGroup()
                        .addComponent(lblFileHint)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(txtOrgFile)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnOrgChoose)))
                .addContainerGap())
        );
        pnlGenTabBodyLayout.setVerticalGroup(
            pnlGenTabBodyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlGenTabBodyLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(lblSelectHint)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlGenTabBodyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtOrgFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnOrgChoose)
                    .addComponent(lblFileHint))
                .addContainerGap(124, Short.MAX_VALUE))
        );

        pnlGenTab.add(pnlGenTabBody, java.awt.BorderLayout.CENTER);

        tabPanel.addTab("Generator Signature", pnlGenTab);

        pnlVerTab.setLayout(new java.awt.BorderLayout());

        lblVerTitle.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        lblVerTitle.setText("Digital Verify Signature");
        pnlVerTabHeader.add(lblVerTitle);

        pnlVerTab.add(pnlVerTabHeader, java.awt.BorderLayout.PAGE_START);

        btnVerify.setText("Verify Signature");
        btnVerify.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnVerifyActionPerformed(evt);
            }
        });
        pnlVerTabFooter.add(btnVerify);

        pnlVerTab.add(pnlVerTabFooter, java.awt.BorderLayout.PAGE_END);

        lblVerifyHine.setText("Select the files");

        lblFileHine.setText("File:");

        btnVerChoose.setText("Browse");
        btnVerChoose.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnVerChooseActionPerformed(evt);
            }
        });

        lblSignHint.setText("Signature:");

        btnSignChoose.setText("Browse");
        btnSignChoose.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSignChooseActionPerformed(evt);
            }
        });

        lblPubHint.setText("Public Key:");

        btnPubkeyChoose.setText("Browse");
        btnPubkeyChoose.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnPubkeyChooseActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout pnlVerTabBodyLayout = new javax.swing.GroupLayout(pnlVerTabBody);
        pnlVerTabBody.setLayout(pnlVerTabBodyLayout);
        pnlVerTabBodyLayout.setHorizontalGroup(
            pnlVerTabBodyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlVerTabBodyLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlVerTabBodyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(pnlVerTabBodyLayout.createSequentialGroup()
                        .addComponent(lblVerifyHine)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(pnlVerTabBodyLayout.createSequentialGroup()
                        .addComponent(lblPubHint)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(txtPubkeyFile, javax.swing.GroupLayout.DEFAULT_SIZE, 240, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnPubkeyChoose))
                    .addGroup(pnlVerTabBodyLayout.createSequentialGroup()
                        .addGroup(pnlVerTabBodyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lblSignHint)
                            .addComponent(lblFileHine))
                        .addGap(12, 12, 12)
                        .addGroup(pnlVerTabBodyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlVerTabBodyLayout.createSequentialGroup()
                                .addComponent(txtVerifyFile)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(btnVerChoose))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlVerTabBodyLayout.createSequentialGroup()
                                .addComponent(txtSignFile)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(btnSignChoose)))))
                .addContainerGap())
        );
        pnlVerTabBodyLayout.setVerticalGroup(
            pnlVerTabBodyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlVerTabBodyLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(lblVerifyHine)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlVerTabBodyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtVerifyFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnVerChoose)
                    .addComponent(lblFileHine))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(pnlVerTabBodyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtSignFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblSignHint)
                    .addComponent(btnSignChoose))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(pnlVerTabBodyLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtPubkeyFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnPubkeyChoose)
                    .addComponent(lblPubHint))
                .addContainerGap(66, Short.MAX_VALUE))
        );

        pnlVerTab.add(pnlVerTabBody, java.awt.BorderLayout.CENTER);

        tabPanel.addTab("Verify Signature", pnlVerTab);

        pnlBody.add(tabPanel);

        getContentPane().add(pnlBody, java.awt.BorderLayout.CENTER);

        pnlFooter.setLayout(new javax.swing.BoxLayout(pnlFooter, javax.swing.BoxLayout.LINE_AXIS));

        pnlStt.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        lblStatus.setText("Status");
        pnlStt.add(lblStatus);

        pnlFooter.add(pnlStt);

        btnExit.setText("Exit");
        btnExit.setPreferredSize(new java.awt.Dimension(66, 23));
        btnExit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnExitActionPerformed(evt);
            }
        });
        pnlFooter.add(btnExit);

        getContentPane().add(pnlFooter, java.awt.BorderLayout.PAGE_END);

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btnOrgChooseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnOrgChooseActionPerformed
        chooseFile(txtOrgFile);
    }//GEN-LAST:event_btnOrgChooseActionPerformed

    private void btnVerChooseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnVerChooseActionPerformed
        chooseFile(txtVerifyFile);
    }//GEN-LAST:event_btnVerChooseActionPerformed

    private void btnSignChooseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSignChooseActionPerformed
        chooseFile(txtSignFile);
    }//GEN-LAST:event_btnSignChooseActionPerformed

    private void btnPubkeyChooseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnPubkeyChooseActionPerformed
        chooseFile(txtPubkeyFile);
    }//GEN-LAST:event_btnPubkeyChooseActionPerformed

    private void btnVerifyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnVerifyActionPerformed
        try {
            //read encoded key from file
            File keyFile = new File(txtPubkeyFile.getText());
            BufferedInputStream keyIn = new BufferedInputStream(new FileInputStream(keyFile));
            byte[] encodedKey = new byte[keyIn.available()];
            keyIn.read(encodedKey);
            keyIn.close();

            //restore public key
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
            PublicKey pubKey = keyFactory.generatePublic(spec);

            //read the sign bytes
            File signFile = new File(txtSignFile.getText());
            BufferedInputStream signIn = new BufferedInputStream(new FileInputStream(signFile));
            byte[] signToVerify = new byte[signIn.available()];
            signIn.read(signToVerify);
            signIn.close();

            //init the sign
            Signature sign = Signature.getInstance("SHA1withDSA", "SUN");
            sign.initVerify(pubKey);

            //suply sign to the data
            File toVerify = new File(txtVerifyFile.getText());
            BufferedInputStream fileIn = new BufferedInputStream(new FileInputStream(toVerify));
            byte[] buf = new byte[1024];
            int len;
            while (fileIn.available() != 0) {
                len = fileIn.read(buf);
                sign.update(buf, 0, len);
            }
            fileIn.close();

            //verify
            boolean verified = sign.verify(signToVerify);

            //message
            if (verified) {
                lblStatus.setText("The file is verified with key successful.");
            } else {
                lblStatus.setText("The file is verified with key. Verify failed");
            }


        }  catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | InvalidKeyException | SignatureException ex) {
            lblStatus.setText(ex.getMessage());
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        }

    }//GEN-LAST:event_btnVerifyActionPerformed

    private void btnGenerateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnGenerateActionPerformed
        try {
            //init keygen
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA", "SUN");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            random.setSeed(System.currentTimeMillis());
            keygen.initialize(1024, random);

            //intit keys pair
            KeyPair pair = keygen.genKeyPair();
            PrivateKey privKey = pair.getPrivate();
            PublicKey pubKey = pair.getPublic();

            //init sign
            Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
            dsa.initSign(privKey);

            //sign the data
            File inputFile = new File(txtOrgFile.getText());
            BufferedInputStream in = new BufferedInputStream(new FileInputStream(inputFile));
            byte[] buf = new byte[1024];
            int len;
            while (in.available() != 0) {
                len = in.read(buf);
                dsa.update(buf, 0, len);
            }
            in.close();

            //general real sign
            byte[] realSig = dsa.sign();

            //write sign to file
            File signFile = new File(inputFile.getParent(), inputFile.getName() + ".sign");
            BufferedOutputStream signOut = new BufferedOutputStream(new FileOutputStream(signFile));
            signOut.write(realSig);
            signOut.close();

            //write key to file
            File keyFile = new File(inputFile.getParent(), inputFile.getName() + ".key");
            BufferedOutputStream keyOut = new BufferedOutputStream(new FileOutputStream(keyFile));
            keyOut.write(pubKey.getEncoded());
            keyOut.close();

            //message
            lblStatus.setText("General Signature Successful");

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException | IOException ex) {
            lblStatus.setText(ex.getMessage());
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_btnGenerateActionPerformed

    private void btnExitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnExitActionPerformed
        System.exit(0);
    }//GEN-LAST:event_btnExitActionPerformed

    public static void main(String args[]) {
        try {
            UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException ex) {
            Logger.getLogger(MainFrame.class.getName()).log(Level.SEVERE, null, ex);
        }
        java.awt.EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                new MainFrame().setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnExit;
    private javax.swing.JButton btnGenerate;
    private javax.swing.JButton btnOrgChoose;
    private javax.swing.JButton btnPubkeyChoose;
    private javax.swing.JButton btnSignChoose;
    private javax.swing.JButton btnVerChoose;
    private javax.swing.JButton btnVerify;
    private javax.swing.JButton jButton4;
    private javax.swing.JLabel lblFileHine;
    private javax.swing.JLabel lblFileHint;
    private javax.swing.JLabel lblGenTitle;
    private javax.swing.JLabel lblPubHint;
    private javax.swing.JLabel lblSelectHint;
    private javax.swing.JLabel lblSignHint;
    private javax.swing.JLabel lblStatus;
    private javax.swing.JLabel lblVerTitle;
    private javax.swing.JLabel lblVerifyHine;
    private javax.swing.JPanel pnlBody;
    private javax.swing.JPanel pnlFooter;
    private javax.swing.JPanel pnlGenTab;
    private javax.swing.JPanel pnlGenTabBody;
    private javax.swing.JPanel pnlGenTabFooter;
    private javax.swing.JPanel pnlGenTabHeader;
    private javax.swing.JPanel pnlStt;
    private javax.swing.JPanel pnlVerTab;
    private javax.swing.JPanel pnlVerTabBody;
    private javax.swing.JPanel pnlVerTabFooter;
    private javax.swing.JPanel pnlVerTabHeader;
    private javax.swing.JTabbedPane tabPanel;
    private javax.swing.JTextField txtOrgFile;
    private javax.swing.JTextField txtPubkeyFile;
    private javax.swing.JTextField txtSignFile;
    private javax.swing.JTextField txtVerifyFile;
    // End of variables declaration//GEN-END:variables

    private void chooseFile(JTextField jTextField) {
        int action = fc.showOpenDialog(this);
        if (action == JFileChooser.APPROVE_OPTION) {
            jTextField.setText(fc.getSelectedFile().getPath());
        }
    }
}
